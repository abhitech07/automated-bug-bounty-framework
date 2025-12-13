"""
Boolean-based SQL injection detection.
"""
import time
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass
import requests

from .payloads import SQLPayloadGenerator, DatabaseType, InjectionType, payload_generator
from .analyzer import SQLResponseAnalyzer, response_analyzer

logger = logging.getLogger(__name__)

@dataclass
class BooleanTestResult:
    """Results of boolean test"""
    true_response: str
    false_response: str
    true_time: float
    false_time: float
    similarity: float
    length_diff: int

class BooleanSQLDetector:
    """Detects boolean-based SQL injection"""
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        self.timeout = timeout
        self.delay = delay
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.payload_pairs = self._create_payload_pairs()
    
    def _create_payload_pairs(self) -> Dict[str, Tuple[str, str]]:
        """Create true/false payload pairs"""
        pairs = {
            'generic_1': ("' OR '1'='1", "' OR '1'='2"),
            'generic_2': ("' OR 1=1", "' OR 1=2"),
            'generic_3': ("' OR 'a'='a", "' OR 'a'='b"),
            'numeric_1': (" OR 1=1", " OR 1=2"),
            'numeric_2': (" OR 2>1", " OR 2<1"),
            'mysql_1': ("' OR 1=1 --", "' OR 1=2 --"),
            'mysql_2': ("' OR IF(1=1,1,0)", "' OR IF(1=2,1,0)"),
            'postgres_1': ("' OR 1=1 --", "' OR 1=2 --"),
            'postgres_2': ("' OR 1::int=1", "' OR 1::int=2"),
            'mssql_1': ("' OR 1=1 --", "' OR 1=2 --"),
            'mssql_2': ("' OR 1=CONVERT(int,1)", "' OR 1=CONVERT(int,2)"),
        }
        return pairs
    
    def test_boolean_injection(self,
                              url: str,
                              parameter: str,
                              original_value: str,
                              method: str = 'GET',
                              param_type: str = 'query') -> List[Dict]:
        """
        Test for boolean-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            original_value: Original parameter value
            method: HTTP method
            param_type: 'query' or 'body'
            
        Returns:
            List of vulnerability findings
        """
        logger.info(f"Testing boolean injection on {parameter}")
        
        findings = []
        
        # Get baseline
        baseline_text, baseline_time = self._get_response(
            url, parameter, original_value, method, param_type
        )
        
        if not baseline_text:
            return findings
        
        # Test each payload pair
        for pair_name, (true_payload, false_payload) in self.payload_pairs.items():
            # Apply delay
            time.sleep(self.delay)
            
            # Test true condition
            true_value = self._adapt_payload(original_value, true_payload)
            true_text, true_time = self._get_response(
                url, parameter, true_value, method, param_type
            )
            
            if not true_text:
                continue
            
            # Test false condition
            time.sleep(self.delay)
            
            false_value = self._adapt_payload(original_value, false_payload)
            false_text, false_time = self._get_response(
                url, parameter, false_value, method, param_type
            )
            
            if not false_text:
                continue
            
            # Analyze results
            result = self._analyze_boolean_results(
                baseline_text=baseline_text,
                true_text=true_text,
                false_text=false_text,
                true_time=true_time,
                false_time=false_time,
                pair_name=pair_name
            )
            
            if result['is_vulnerable']:
                findings.append({
                    'parameter': parameter,
                    'true_payload': true_payload,
                    'false_payload': false_payload,
                    'confidence': result['confidence'],
                    'evidence': result['evidence'],
                    'pair_name': pair_name,
                })
                
                logger.info(f"  Found boolean injection with {pair_name} (confidence: {result['confidence']:.2f})")
        
        return findings
    
    def _get_response(self,
                     url: str,
                     parameter: str,
                     value: str,
                     method: str,
                     param_type: str) -> Tuple[Optional[str], float]:
        """Get HTTP response for parameter value"""
        try:
            if param_type == 'query':
                params = {parameter: value}
                if method.upper() == 'GET':
                    response = self.session.get(
                        url, params=params, timeout=self.timeout
                    )
                else:
                    response = self.session.post(
                        url, data=params, timeout=self.timeout
                    )
            else:
                data = {parameter: value}
                response = self.session.post(
                    url, data=data, timeout=self.timeout
                )
            
            return response.text, response.elapsed.total_seconds() * 1000
            
        except requests.RequestException as e:
            logger.debug(f"Request failed: {e}")
            return None, 0.0
    
    def _adapt_payload(self, original_value: str, payload: str) -> str:
        """Adapt payload to original value type"""
        if original_value.isdigit():
            # Remove quotes for numeric parameters
            payload = payload.replace("'", "").replace("\"", "")
            return f"{original_value}{payload}"
        else:
            return f"{original_value}{payload}"
    
    def _analyze_boolean_results(self,
                                baseline_text: str,
                                true_text: str,
                                false_text: str,
                                true_time: float,
                                false_time: float,
                                pair_name: str) -> Dict:
        """
        Analyze boolean test results.
        
        Returns:
            Dictionary with vulnerability analysis
        """
        # Calculate similarities
        similarity_true = response_analyzer._calculate_similarity(baseline_text, true_text)
        similarity_false = response_analyzer._calculate_similarity(baseline_text, false_text)
        similarity_true_false = response_analyzer._calculate_similarity(true_text, false_text)
        
        # Check for differences
        true_different = similarity_true < 0.95
        false_different = similarity_false < 0.95
        
        # Boolean logic: true and false should produce different responses
        boolean_different = similarity_true_false < 0.9
        
        # Calculate confidence
        confidence = 0.0
        
        if boolean_different:
            confidence += 0.4
        
        if true_different and not false_different:
            confidence += 0.3
        elif not true_different and false_different:
            confidence += 0.2
        
        # Check for time differences
        time_diff = abs(true_time - false_time)
        if time_diff > 1000:  # More than 1 second difference
            confidence += 0.2
        
        # Check for content length patterns
        true_len = len(true_text)
        false_len = len(false_text)
        len_diff = abs(true_len - false_len)
        
        if len_diff > 100:  # Significant length difference
            confidence += 0.1
        
        # Check for SQL errors
        true_errors = response_analyzer._check_sql_errors(true_text)
        false_errors = response_analyzer._check_sql_errors(false_text)
        
        if true_errors or false_errors:
            confidence += 0.1
        
        is_vulnerable = confidence > 0.5
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': min(1.0, confidence),
            'evidence': {
                'similarity_true': similarity_true,
                'similarity_false': similarity_false,
                'similarity_true_false': similarity_true_false,
                'true_different': true_different,
                'false_different': false_different,
                'boolean_different': boolean_different,
                'time_difference_ms': time_diff,
                'length_difference': len_diff,
                'true_errors': len(true_errors) > 0,
                'false_errors': len(false_errors) > 0,
                'true_response_time': true_time,
                'false_response_time': false_time,
            }
        }
    
    def _heuristic_analysis(self, true_text: str, false_text: str) -> float:
        """
        Heuristic analysis of boolean responses.
        
        Returns:
            Additional confidence score
        """
        score = 0.0
        
        # Check for common boolean indicators
        true_indicators = [
            "welcome", "success", "logged in", "admin",
            "exists", "found", "valid", "correct"
        ]
        
        false_indicators = [
            "error", "invalid", "not found", "failed",
            "incorrect", "wrong", "access denied"
        ]
        
        true_lower = true_text.lower()
        false_lower = false_text.lower()
        
        for indicator in true_indicators:
            if indicator in true_lower:
                score += 0.05
        
        for indicator in false_indicators:
            if indicator in false_lower:
                score += 0.05
        
        # Check for different status messages
        status_patterns = [
            (r"(\d+) results?", "result_count"),
            (r"(\d+) records?", "record_count"),
            (r"(\d+) items?", "item_count"),
        ]
        
        for pattern, name in status_patterns:
            import re
            true_match = re.search(pattern, true_lower)
            false_match = re.search(pattern, false_lower)
            
            if true_match and false_match:
                true_count = int(true_match.group(1))
                false_count = int(false_match.group(1))
                
                if true_count != false_count:
                    score += 0.1
        
        return min(0.3, score)  # Cap heuristic score

# Test function
def test_boolean_detector():
    """Test boolean-based detection"""
    print("\nTesting Boolean SQL Injection Detector")
    print("=" * 60)
    
    detector = BooleanSQLDetector(timeout=5, delay=1.0)
    
    # Test payload adaptation
    print("\n1. Testing payload adaptation:")
    test_cases = [
        ("123", "' OR '1'='1"),
        ("test", "' OR '1'='1"),
        ("", "' OR 1=1"),
    ]
    
    for original, payload in test_cases:
        adapted = detector._adapt_payload(original, payload)
        print(f"   '{original}' + '{payload}' -> '{adapted}'")
    
    # Test boolean analysis
    print("\n2. Testing boolean analysis:")
    
    # Simulate responses
    baseline = "Welcome to our site"
    true_response = "Welcome admin! You have 10 messages"
    false_response = "Error: Invalid credentials"
    
    result = detector._analyze_boolean_results(
        baseline_text=baseline,
        true_text=true_response,
        false_text=false_response,
        true_time=100,
        false_time=150,
        pair_name="test"
    )
    
    print(f"   Vulnerability: {result['is_vulnerable']}")
    print(f"   Confidence: {result['confidence']:.2f}")
    print(f"   Evidence keys: {list(result['evidence'].keys())}")
    
    return True

if __name__ == "__main__":
    test_boolean_detector()