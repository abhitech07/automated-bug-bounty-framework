"""
Advanced boolean-based SQL injection testing.
"""
import time
import hashlib
from typing import List, Dict, Tuple, Optional, Set
import logging
from dataclasses import dataclass
from collections import defaultdict
import difflib

from .response_analyzer import SQLiResponseAnalyzer, ResponseSignature
from .payloads import SQLiPayloads

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BooleanTestResult:
    """Results from boolean-based testing"""
    parameter: str
    true_payload: str
    false_payload: str
    is_vulnerable: bool
    confidence: float
    evidence: Dict
    inferred_database: Optional[str] = None
    inferred_query_structure: Optional[str] = None

class BooleanSQLiTester:
    """Advanced boolean-based SQL injection tester"""
    
    def __init__(self, analyzer: SQLiResponseAnalyzer = None):
        self.analyzer = analyzer or SQLiResponseAnalyzer()
        self.payloads = SQLiPayloads()
        
        # Response similarity cache
        self.response_cache: Dict[str, ResponseSignature] = {}
        
        # Database-specific patterns for inference
        self.db_specific_patterns = {
            'mysql': [
                ("' AND '1'='1", "' AND '1'='2"),
                ("1' AND '1'='1", "1' AND '1'='2"),
                ("' AND 1=1", "' AND 1=2"),
            ],
            'postgresql': [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND '1'='1'--", "' AND '1'='2'--"),
            ],
            'mssql': [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND '1'='1'--", "' AND '1'='2'--"),
            ],
            'oracle': [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND '1'='1'--", "' AND '1'='2'--"),
            ]
        }
    
    def generate_boolean_payload_pairs(self, db_type: str = None) -> List[Tuple[str, str]]:
        """
        Generate true/false payload pairs for boolean testing.
        
        Args:
            db_type: Specific database type for targeted payloads
            
        Returns:
            List of (true_payload, false_payload) tuples
        """
        pairs = []
        
        # Get all boolean payloads
        all_payloads = self.payloads.get_payloads_by_technique('boolean', db_type)
        
        # Group similar payloads for pairing
        grouped = defaultdict(list)
        for payload in all_payloads:
            # Extract the base pattern (remove specific values)
            base = payload.replace("'1'", "'X'").replace("1=1", "X=X").replace("1=2", "X=Y")
            grouped[base].append(payload)
        
        # Create pairs from groups
        for base_pattern, payload_list in grouped.items():
            if len(payload_list) >= 2:
                # Try to find logical true/false pairs
                for i in range(len(payload_list)):
                    for j in range(i+1, len(payload_list)):
                        p1, p2 = payload_list[i], payload_list[j]
                        
                        # Check if they look like true/false pairs
                        if self._is_logical_pair(p1, p2):
                            # Determine which is true and which is false
                            if self._is_likely_true(p1) and self._is_likely_false(p2):
                                pairs.append((p1, p2))
                            elif self._is_likely_true(p2) and self._is_likely_false(p1):
                                pairs.append((p2, p1))
        
        # If no pairs found, generate generic pairs
        if not pairs and all_payloads:
            for i in range(0, len(all_payloads) - 1, 2):
                pairs.append((all_payloads[i], all_payloads[i+1]))
        
        return pairs
    
    def _is_logical_pair(self, p1: str, p2: str) -> bool:
        """Check if two payloads are logical opposites"""
        p1_clean = p1.lower().replace(' ', '')
        p2_clean = p2.lower().replace(' ', '')
        
        # Common logical opposites
        opposites = [
            ('1=1', '1=2'),
            ("'1'='1'", "'1'='2'"),
            ('true', 'false'),
            ('1', '0'),
        ]
        
        for true_str, false_str in opposites:
            if true_str in p1_clean and false_str in p2_clean:
                return True
            if true_str in p2_clean and false_str in p1_clean:
                return True
        
        return False
    
    def _is_likely_true(self, payload: str) -> bool:
        """Determine if a payload is likely a TRUE condition"""
        true_indicators = ['1=1', "'1'='1'", 'true', '1--']
        payload_lower = payload.lower()
        
        for indicator in true_indicators:
            if indicator in payload_lower:
                return True
        
        return False
    
    def _is_likely_false(self, payload: str) -> bool:
        """Determine if a payload is likely a FALSE condition"""
        false_indicators = ['1=2', "'1'='2'", 'false', '0--']
        payload_lower = payload.lower()
        
        for indicator in false_indicators:
            if indicator in payload_lower:
                return True
        
        return False
    
    def calculate_content_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two texts using multiple methods.
        
        Args:
            text1: First text
            text2: Second text
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not text1 or not text2:
            return 0.0
        
        # Method 1: SequenceMatcher (character-based)
        seq_matcher = difflib.SequenceMatcher(None, text1, text2)
        char_similarity = seq_matcher.ratio()
        
        # Method 2: Word-based similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            word_similarity = 0.0
        else:
            common = words1.intersection(words2)
            word_similarity = len(common) / max(len(words1), len(words2))
        
        # Method 3: Line-based similarity
        lines1 = text1.split('\n')
        lines2 = text2.split('\n')
        
        if not lines1 or not lines2:
            line_similarity = 0.0
        else:
            line_matcher = difflib.SequenceMatcher(None, lines1, lines2)
            line_similarity = line_matcher.ratio()
        
        # Method 4: Structural similarity (HTML tags, etc.)
        structural_sim = self._calculate_structural_similarity(text1, text2)
        
        # Weighted average
        weights = {
            'char': 0.3,
            'word': 0.3,
            'line': 0.2,
            'structural': 0.2
        }
        
        similarity = (
            char_similarity * weights['char'] +
            word_similarity * weights['word'] +
            line_similarity * weights['line'] +
            structural_sim * weights['structural']
        )
        
        return similarity
    
    def _calculate_structural_similarity(self, text1: str, text2: str) -> float:
        """Calculate structural similarity (HTML tags, patterns)"""
        # Extract structural elements
        def extract_structure(text: str) -> Dict[str, int]:
            import re
            structure = {
                'html_tags': len(re.findall(r'<[^>]+>', text)),
                'div_tags': len(re.findall(r'<div[^>]*>', text, re.IGNORECASE)),
                'form_tags': len(re.findall(r'<form[^>]*>', text, re.IGNORECASE)),
                'input_tags': len(re.findall(r'<input[^>]*>', text, re.IGNORECASE)),
                'table_tags': len(re.findall(r'<table[^>]*>', text, re.IGNORECASE)),
                'paragraphs': len(re.findall(r'<p[^>]*>', text, re.IGNORECASE)),
                'links': len(re.findall(r'<a[^>]*>', text, re.IGNORECASE)),
            }
            return structure
        
        struct1 = extract_structure(text1)
        struct2 = extract_structure(text2)
        
        # Calculate similarity for each structural element
        similarities = []
        for key in struct1:
            if struct1[key] == 0 and struct2[key] == 0:
                similarities.append(1.0)  # Both have zero of this element
            elif struct1[key] == 0 or struct2[key] == 0:
                similarities.append(0.0)  # One has it, other doesn't
            else:
                # Use ratio for non-zero counts
                ratio = min(struct1[key], struct2[key]) / max(struct1[key], struct2[key])
                similarities.append(ratio)
        
        return sum(similarities) / len(similarities) if similarities else 0.0
    
    def detect_response_patterns(self, true_response: str, false_response: str, 
                                baseline_response: str) -> Dict[str, any]:
        """
        Detect patterns in responses that indicate SQL injection.
        
        Args:
            true_response: Response with TRUE condition
            false_response: Response with FALSE condition
            baseline_response: Baseline response without injection
            
        Returns:
            Dictionary of detected patterns
        """
        patterns = {
            'content_length_diff': abs(len(true_response) - len(false_response)),
            'status_code_diff': 0,  # Will be set if status codes differ
            'true_baseline_similarity': self.calculate_content_similarity(true_response, baseline_response),
            'false_baseline_similarity': self.calculate_content_similarity(false_response, baseline_response),
            'true_false_similarity': self.calculate_content_similarity(true_response, false_response),
            'has_error_messages': False,
            'has_different_titles': False,
            'has_different_forms': False,
        }
        
        # Check for different status codes
        # (This would require HTTP status codes, which we don't have in this method)
        # Patterns will be updated by the calling method
        
        # Check for error messages
        error_keywords = ['error', 'exception', 'warning', 'invalid', 'sql', 'syntax']
        for keyword in error_keywords:
            if keyword in true_response.lower() or keyword in false_response.lower():
                patterns['has_error_messages'] = True
                break
        
        # Check for different titles
        import re
        title1 = re.search(r'<title[^>]*>(.*?)</title>', true_response, re.IGNORECASE)
        title2 = re.search(r'<title[^>]*>(.*?)</title>', false_response, re.IGNORECASE)
        
        if title1 and title2:
            patterns['has_different_titles'] = title1.group(1) != title2.group(1)
        
        # Check for different forms
        forms1 = re.findall(r'<form[^>]*>', true_response, re.IGNORECASE)
        forms2 = re.findall(r'<form[^>]*>', false_response, re.IGNORECASE)
        patterns['has_different_forms'] = len(forms1) != len(forms2)
        
        return patterns
    
    def infer_database_type(self, true_payload: str, false_payload: str, 
                           response_patterns: Dict) -> Tuple[Optional[str], float]:
        """
        Infer database type from payloads and response patterns.
        
        Args:
            true_payload: TRUE condition payload
            false_payload: FALSE condition payload
            response_patterns: Detected response patterns
            
        Returns:
            Tuple of (database_type, confidence)
        """
        # Check payload patterns first
        for db_type, patterns in self.db_specific_patterns.items():
            for true_pattern, false_pattern in patterns:
                if (true_pattern in true_payload and false_pattern in false_payload):
                    return db_type, 0.8
        
        # Check for specific database keywords in error messages
        db_keywords = {
            'mysql': ['mysql', 'mysqli', 'mariadb'],
            'postgresql': ['postgres', 'postgresql', 'pg_'],
            'mssql': ['mssql', 'sql server', 'tsql', 'sybase'],
            'oracle': ['oracle', 'pl/sql', 'oci_'],
        }
        
        # This would require access to response text with errors
        # For now, return unknown
        return None, 0.0
    
    def infer_query_structure(self, parameter: str, payload: str) -> Optional[str]:
        """
        Infer the structure of the SQL query being injected.
        
        Args:
            parameter: Parameter name
            payload: Successful payload
            
        Returns:
            Inferred query structure or None
        """
        # Common query patterns
        patterns = [
            # Numeric parameter in WHERE clause
            (r"(\d+)", f"SELECT * FROM table WHERE id = {{{{parameter}}}}"),
            
            # String parameter in WHERE clause
            (r"'.*'", f"SELECT * FROM table WHERE column = '{{{{parameter}}}}'"),
            
            # LIKE query
            (r".*%.*", f"SELECT * FROM table WHERE column LIKE '%{{{{parameter}}}}%'"),
            
            # ORDER BY injection
            (r"ASC|DESC", f"SELECT * FROM table ORDER BY {{{{parameter}}}}"),
            
            # LIMIT injection
            (r"\d+,\d+", f"SELECT * FROM table LIMIT {{{{parameter}}}}"),
        ]
        
        for pattern, structure in patterns:
            import re
            if re.search(pattern, payload):
                return structure.replace("{{parameter}}", parameter)
        
        return None
    
    def test_parameter(self, url: str, parameter: str, method: str,
                      get_params: Dict, post_data: Dict, 
                      session, baseline_response: str) -> List[BooleanTestResult]:
        """
        Test a single parameter for boolean-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            get_params: GET parameters
            post_data: POST data
            session: Requests session
            baseline_response: Baseline response text
            
        Returns:
            List of BooleanTestResult objects
        """
        results = []
        
        # Get payload pairs for testing
        payload_pairs = self.generate_boolean_payload_pairs()
        
        for true_payload, false_payload in payload_pairs[:5]:  # Limit to 5 pairs for speed
            try:
                logger.info(f"Testing {parameter} with boolean pair: {true_payload[:30]}... / {false_payload[:30]}...")
                
                # Send TRUE request
                true_response = self._send_request(
                    url, parameter, true_payload, method, 
                    get_params, post_data, session
                )
                
                if not true_response:
                    continue
                
                # Send FALSE request
                false_response = self._send_request(
                    url, parameter, false_payload, method,
                    get_params, post_data, session
                )
                
                if not false_response:
                    continue
                
                # Analyze responses
                is_vulnerable, confidence, evidence = self._analyze_boolean_responses(
                    true_response, false_response, baseline_response,
                    true_payload, false_payload
                )
                
                if is_vulnerable:
                    # Infer database type
                    db_type, db_confidence = self.infer_database_type(
                        true_payload, false_payload, evidence
                    )
                    
                    # Infer query structure
                    query_structure = self.infer_query_structure(parameter, true_payload)
                    
                    result = BooleanTestResult(
                        parameter=parameter,
                        true_payload=true_payload,
                        false_payload=false_payload,
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=evidence,
                        inferred_database=db_type,
                        inferred_query_structure=query_structure
                    )
                    
                    results.append(result)
                    
                    # Log finding
                    logger.info(f"✅ Potential boolean-based SQLi found in {parameter}")
                    logger.info(f"   Confidence: {confidence:.2f}")
                    if db_type:
                        logger.info(f"   Inferred DB: {db_type}")
                
            except Exception as e:
                logger.error(f"Error testing {parameter}: {e}")
                continue
        
        return results
    
    def _send_request(self, url: str, param_name: str, payload: str, 
                     method: str, get_params: Dict, post_data: Dict, session) -> Optional[Dict]:
        """
        Send a request with the injected payload.
        
        Returns:
            Dictionary with response data or None if failed
        """
        import time
        from copy import deepcopy
        
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                params = deepcopy(get_params) if get_params else {}
                params[param_name] = payload
                
                response = session.get(url, params=params, timeout=10)
            else:  # POST
                data = deepcopy(post_data) if post_data else {}
                data[param_name] = payload
                
                response = session.post(url, data=data, timeout=10)
            
            elapsed = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'elapsed': elapsed,
                'url': response.url,
                'content_length': len(response.text)
            }
            
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def _analyze_boolean_responses(self, true_resp: Dict, false_resp: Dict,
                                 baseline_resp: str, true_payload: str,
                                 false_payload: str) -> Tuple[bool, float, Dict]:
        """
        Analyze boolean responses for SQL injection indicators.
        
        Returns:
            Tuple of (is_vulnerable, confidence, evidence)
        """
        evidence = {
            'true_response': {
                'status_code': true_resp['status_code'],
                'content_length': true_resp['content_length'],
                'response_time': true_resp['elapsed']
            },
            'false_response': {
                'status_code': false_resp['status_code'],
                'content_length': false_resp['content_length'],
                'response_time': false_resp['elapsed']
            },
            'differences': {}
        }
        
        # Check for obvious differences
        differences = []
        
        # 1. Different status codes (strong indicator)
        if true_resp['status_code'] != false_resp['status_code']:
            differences.append('status_code')
            evidence['differences']['status_code'] = {
                'true': true_resp['status_code'],
                'false': false_resp['status_code']
            }
        
        # 2. Significant content length difference (> 10%)
        length_diff = abs(true_resp['content_length'] - false_resp['content_length'])
        avg_length = (true_resp['content_length'] + false_resp['content_length']) / 2
        
        if avg_length > 0 and (length_diff / avg_length) > 0.1:
            differences.append('content_length')
            evidence['differences']['content_length'] = {
                'true': true_resp['content_length'],
                'false': false_resp['content_length'],
                'difference': length_diff,
                'percentage': (length_diff / avg_length) * 100
            }
        
        # 3. Content similarity analysis
        content_similarity = self.calculate_content_similarity(
            true_resp['text'], false_resp['text']
        )
        
        evidence['differences']['content_similarity'] = content_similarity
        
        if content_similarity < 0.7:  # Less than 70% similar
            differences.append('content')
        
        # 4. Compare with baseline
        true_baseline_sim = self.calculate_content_similarity(
            true_resp['text'], baseline_resp
        )
        false_baseline_sim = self.calculate_content_similarity(
            false_resp['text'], baseline_resp
        )
        
        evidence['differences']['baseline_similarity'] = {
            'true': true_baseline_sim,
            'false': false_baseline_sim
        }
        
        # Determine if vulnerable
        is_vulnerable = False
        confidence = 0.0
        
        if differences:
            is_vulnerable = True
            
            # Calculate confidence based on differences
            confidence_factors = []
            
            if 'status_code' in differences:
                confidence_factors.append(0.8)  # Strong indicator
            
            if 'content_length' in differences:
                # Stronger confidence for larger differences
                diff_strength = min(evidence['differences']['content_length']['percentage'] / 50, 1.0)
                confidence_factors.append(0.3 + (0.4 * diff_strength))
            
            if 'content' in differences:
                # Lower similarity = higher confidence
                content_confidence = 0.6 + (0.3 * (1 - content_similarity))
                confidence_factors.append(content_confidence)
            
            # Average the confidence factors
            if confidence_factors:
                confidence = sum(confidence_factors) / len(confidence_factors)
            
            # Adjust based on baseline comparison
            if true_baseline_sim < 0.8 and false_baseline_sim < 0.8:
                # Both responses differ from baseline
                confidence = min(confidence * 1.2, 0.95)
        
        return is_vulnerable, confidence, evidence

# Test function
def test_boolean_tester():
    """Test the boolean tester"""
    tester = BooleanSQLiTester()
    
    # Generate payload pairs
    pairs = tester.generate_boolean_payload_pairs()
    print(f"Generated {len(pairs)} boolean payload pairs")
    
    if pairs:
        print("\nFirst 3 pairs:")
        for i, (true_p, false_p) in enumerate(pairs[:3]):
            print(f"{i+1}. TRUE: {true_p}")
            print(f"   FALSE: {false_p}")
    
    # Test content similarity
    text1 = "Hello world this is a test"
    text2 = "Hello world this is another test"
    similarity = tester.calculate_content_similarity(text1, text2)
    print(f"\nContent similarity: {similarity:.2f}")
    
    return tester

if __name__ == "__main__":
    test_boolean_tester()