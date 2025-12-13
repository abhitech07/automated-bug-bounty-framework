"""
Core SQL injection scanner.
"""
import time
import requests
from typing import List, Dict, Optional, Tuple, Any
import logging
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .payloads import SQLiPayloads
from .response_analyzer import SQLiResponseAnalyzer, ResponseSignature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SQLiFinding:
    """Data class for SQL injection findings"""
    url: str
    parameter: str
    payload: str
    technique: str  # 'boolean', 'error', 'time', 'union'
    confidence: float
    evidence: Dict[str, Any]
    database_type: Optional[str] = None
    is_verified: bool = False
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

class SQLiScanner:
    """SQL injection scanner with multiple detection techniques"""
    
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 2,
        delay: float = 1.0,
        user_agent: str = None,
        enable_techniques: List[str] = None
    ):
        """
        Initialize the SQLi scanner.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            delay: Delay between requests
            user_agent: Custom User-Agent header
            enable_techniques: List of techniques to enable
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        self.enable_techniques = enable_techniques or ['boolean', 'error', 'time']
        self.payloads = SQLiPayloads()
        self.analyzer = SQLiResponseAnalyzer()
        
        # Store baseline response for comparison
        self.baseline_responses: Dict[str, ResponseSignature] = {}
        
    def get_baseline_response(self, url: str, method: str = 'GET', 
                             params: Dict = None, data: Dict = None) -> ResponseSignature:
        """
        Get baseline response without any injection.
        
        Args:
            url: Target URL
            method: HTTP method
            params: URL parameters
            data: POST data
            
        Returns:
            ResponseSignature of baseline response
        """
        cache_key = f"{method}:{url}:{str(params)}:{str(data)}"
        
        if cache_key in self.baseline_responses:
            return self.baseline_responses[cache_key]
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url, 
                    params=params,
                    timeout=self.timeout
                )
            else:
                response = self.session.post(
                    url,
                    params=params,
                    data=data,
                    timeout=self.timeout
                )
            
            signature = self.analyzer.create_signature(
                response.text,
                response.status_code
            )
            
            self.baseline_responses[cache_key] = signature
            return signature
            
        except requests.RequestException as e:
            logger.error(f"Failed to get baseline for {url}: {e}")
            # Return empty signature on error
            return self.analyzer.create_signature("", 0)
    
    def inject_payload(self, url: str, param_name: str, payload: str, 
                      method: str = 'GET', original_params: Dict = None,
                      original_data: Dict = None) -> Optional[requests.Response]:
        """
        Inject a payload into a parameter and send request.
        
        Args:
            url: Target URL
            param_name: Parameter name to inject into
            payload: SQLi payload
            method: HTTP method
            original_params: Original URL parameters (GET)
            original_data: Original form data (POST)
            
        Returns:
            Response object or None if failed
        """
        try:
            # For GET requests, modify URL parameters
            if method.upper() == 'GET':
                params = original_params.copy() if original_params else {}
                params[param_name] = payload
                
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout
                )
            
            # For POST requests, modify form data
            else:
                data = original_data.copy() if original_data else {}
                data[param_name] = payload
                
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout
                )
            
            # Respect delay between requests
            time.sleep(self.delay)
            
            return response
            
        except requests.RequestException as e:
            logger.error(f"Request failed for {url} with payload {payload}: {e}")
            return None
    
    def test_boolean_based(self, url: str, param_name: str, method: str = 'GET',
                          params: Dict = None, data: Dict = None) -> List[SQLiFinding]:
        """
        Test for boolean-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter to test
            method: HTTP method
            params: GET parameters
            data: POST data
            
        Returns:
            List of SQLiFinding objects
        """
        findings = []
        
        # Get baseline response
        baseline_sig = self.get_baseline_response(url, method, params, data)
        
        # Test boolean payload pairs
        boolean_payloads = self.payloads.get_payloads_by_technique('boolean')
        
        for i in range(0, len(boolean_payloads), 2):
            if i + 1 >= len(boolean_payloads):
                break
            
            true_payload = boolean_payloads[i]
            false_payload = boolean_payloads[i + 1]
            
            logger.info(f"Testing boolean-based: {true_payload} / {false_payload}")
            
            # Send TRUE condition request
            true_response = self.inject_payload(
                url, param_name, true_payload, method, params, data
            )
            
            if not true_response:
                continue
            
            true_sig = self.analyzer.create_signature(
                true_response.text,
                true_response.status_code
            )
            
            # Send FALSE condition request
            false_response = self.inject_payload(
                url, param_name, false_payload, method, params, data
            )
            
            if not false_response:
                continue
            
            false_sig = self.analyzer.create_signature(
                false_response.text,
                false_response.status_code
            )
            
            # Compare TRUE and FALSE responses
            is_vulnerable, confidence = self.analyzer.is_boolean_based_vulnerable(
                true_sig, false_sig
            )
            
            if is_vulnerable and confidence > 0.6:
                # Compare with baseline to ensure it's not a false positive
                true_baseline_diff = self.analyzer.compare_responses(true_sig, baseline_sig)
                false_baseline_diff = self.analyzer.compare_responses(false_sig, baseline_sig)
                
                # Only report if responses differ from baseline
                if (true_baseline_diff['overall'] < 0.9 or 
                    false_baseline_diff['overall'] < 0.9):
                    
                    finding = SQLiFinding(
                        url=url,
                        parameter=param_name,
                        payload=f"{true_payload} / {false_payload}",
                        technique='boolean',
                        confidence=confidence,
                        evidence={
                            'true_response': {
                                'status_code': true_response.status_code,
                                'content_length': len(true_response.text),
                                'similarity_with_baseline': true_baseline_diff['overall']
                            },
                            'false_response': {
                                'status_code': false_response.status_code,
                                'content_length': len(false_response.text),
                                'similarity_with_baseline': false_baseline_diff['overall']
                            },
                            'true_false_similarity': self.analyzer.compare_responses(
                                true_sig, false_sig
                            )['overall']
                        }
                    )
                    findings.append(finding)
        
        return findings
    
    def test_error_based(self, url: str, param_name: str, method: str = 'GET',
                        params: Dict = None, data: Dict = None) -> List[SQLiFinding]:
        """
        Test for error-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter to test
            method: HTTP method
            params: GET parameters
            data: POST data
            
        Returns:
            List of SQLiFinding objects
        """
        findings = []
        
        # Get baseline response
        baseline_sig = self.get_baseline_response(url, method, params, data)
        
        # Test error payloads
        error_payloads = self.payloads.get_payloads_by_technique('error')
        
        for payload in error_payloads[:10]:  # Limit to first 10 for speed
            logger.info(f"Testing error-based: {payload}")
            
            response = self.inject_payload(
                url, param_name, payload, method, params, data
            )
            
            if not response:
                continue
            
            # Check for SQL errors in response
            is_vulnerable, confidence, errors = self.analyzer.is_error_based_vulnerable(
                response.text
            )
            
            if is_vulnerable:
                # Compare with baseline
                response_sig = self.analyzer.create_signature(
                    response.text,
                    response.status_code
                )
                
                baseline_diff = self.analyzer.compare_responses(response_sig, baseline_sig)
                
                # Determine database type from errors
                db_type = None
                if errors:
                    # Prioritize specific DB types over generic
                    specific_dbs = [db for db in errors if db != 'generic']
                    db_type = specific_dbs[0] if specific_dbs else 'generic'
                
                finding = SQLiFinding(
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    technique='error',
                    confidence=confidence,
                    database_type=db_type,
                    evidence={
                        'status_code': response.status_code,
                        'detected_errors': errors,
                        'similarity_with_baseline': baseline_diff['overall'],
                        'error_count': sum(len(e) for e in errors.values())
                    }
                )
                findings.append(finding)
        
        return findings
    
    def test_time_based(self, url: str, param_name: str, method: str = 'GET',
                       params: Dict = None, data: Dict = None,
                       delay_seconds: int = 5) -> List[SQLiFinding]:
        """
        Test for time-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter to test
            method: HTTP method
            params: GET parameters
            data: POST data
            delay_seconds: Expected delay in payload
            
        Returns:
            List of SQLiFinding objects
        """
        findings = []
        
        # Test time payloads for different databases
        for db_type in ['mysql', 'postgresql', 'mssql', 'oracle']:
            time_payloads = self.payloads.get_payloads_by_technique('time', db_type)
            
            for payload in time_payloads[:3]:  # Test first 3 per DB type
                logger.info(f"Testing time-based ({db_type}): {payload}")
                
                # Measure response time
                start_time = time.time()
                
                response = self.inject_payload(
                    url, param_name, payload, method, params, data
                )
                
                elapsed = time.time() - start_time
                
                if response and elapsed >= delay_seconds - 1:  # Account for network latency
                    # Perform confirmation test
                    confirmation_payload = payload.replace(str(delay_seconds), str(delay_seconds * 2))
                    
                    start_time2 = time.time()
                    response2 = self.inject_payload(
                        url, param_name, confirmation_payload, method, params, data
                    )
                    elapsed2 = time.time() - start_time2
                    
                    # If second request takes roughly twice as long, it's likely valid
                    if (elapsed2 >= (delay_seconds * 2) - 2 and 
                        abs(elapsed2 - (elapsed * 2)) < 3):
                        
                        confidence = min(0.8 + (elapsed - delay_seconds) / 10, 0.95)
                        
                        finding = SQLiFinding(
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            technique='time',
                            confidence=confidence,
                            database_type=db_type,
                            evidence={
                                'first_request_time': elapsed,
                                'second_request_time': elapsed2,
                                'expected_delay': delay_seconds,
                                'status_code': response.status_code
                            }
                        )
                        findings.append(finding)
        
        return findings
    
    def scan_url(self, url: str, method: str = 'GET', 
                params: Dict = None, data: Dict = None) -> List[SQLiFinding]:
        """
        Scan a URL for SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method
            params: GET parameters (dictionary)
            data: POST data (dictionary)
            
        Returns:
            List of SQLiFinding objects
        """
        findings = []
        
        # Determine which parameters to test
        parameters_to_test = []
        
        if method.upper() == 'GET' and params:
            parameters_to_test = list(params.keys())
        elif method.upper() == 'POST' and data:
            parameters_to_test = list(data.keys())
        
        if not parameters_to_test:
            logger.warning(f"No parameters found to test for {url}")
            return findings
        
        logger.info(f"Starting SQLi scan for {url}")
        logger.info(f"Parameters to test: {parameters_to_test}")
        
        # Test each parameter with enabled techniques
        for param in parameters_to_test:
            logger.info(f"Testing parameter: {param}")
            
            if 'boolean' in self.enable_techniques:
                boolean_findings = self.test_boolean_based(
                    url, param, method, params, data
                )
                findings.extend(boolean_findings)
            
            if 'error' in self.enable_techniques:
                error_findings = self.test_error_based(
                    url, param, method, params, data
                )
                findings.extend(error_findings)
            
            if 'time' in self.enable_techniques:
                time_findings = self.test_time_based(
                    url, param, method, params, data
                )
                findings.extend(time_findings)
        
        # Sort findings by confidence (highest first)
        findings.sort(key=lambda x: x.confidence, reverse=True)
        
        logger.info(f"SQLi scan complete. Found {len(findings)} potential vulnerabilities.")
        return findings

# Test function
def test_sqli_scanner():
    """Test the SQLi scanner"""
    scanner = SQLiScanner(
        timeout=5,
        delay=0.5,
        enable_techniques=['boolean', 'error']  # Skip time-based for quick test
    )
    
    # Test against a known vulnerable test site
    # Note: Use only authorized test sites!
    test_url = "http://testphp.vulnweb.com/artists.php"
    test_params = {"artist": "1"}
    
    print(f"Testing SQLi scanner on: {test_url}")
    findings = scanner.scan_url(test_url, method='GET', params=test_params)
    
    print(f"\nFound {len(findings)} potential SQLi vulnerabilities:")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. Parameter: {finding.parameter}")
        print(f"   Technique: {finding.technique}")
        print(f"   Confidence: {finding.confidence:.2f}")
        print(f"   Payload: {finding.payload[:50]}...")
        if finding.database_type:
            print(f"   DB Type: {finding.database_type}")
    
    return findings

if __name__ == "__main__":
    findings = test_sqli_scanner()