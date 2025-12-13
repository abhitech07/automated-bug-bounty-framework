"""
Base SQL injection detector class.
"""
import time
import requests
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .payloads import SQLPayloadGenerator, DatabaseType, InjectionType, payload_generator
from .analyzer import SQLResponseAnalyzer, ResponseAnalysis, response_analyzer

logger = logging.getLogger(__name__)

@dataclass
class SQLInjectionResult:
    """Results of SQL injection detection"""
    url: str
    parameter: str
    payload: str
    injection_type: str
    database_type: str
    confidence: float
    evidence: Dict
    request: Optional[Dict] = None
    response: Optional[Dict] = None

class SQLInjectionDetector:
    """Base class for SQL injection detection"""
    
    def __init__(self, 
                 timeout: int = 10,
                 max_requests: int = 100,
                 delay: float = 0.5):
        """
        Initialize SQL injection detector.
        
        Args:
            timeout: Request timeout in seconds
            max_requests: Maximum requests per parameter
            delay: Delay between requests in seconds
        """
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Results storage
        self.results: List[SQLInjectionResult] = []
        
        # Statistics
        self.stats = {
            'requests_made': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
        }
    
    def send_request(self, 
                    url: str, 
                    method: str = 'GET',
                    params: Optional[Dict] = None,
                    data: Optional[Dict] = None) -> Tuple[Optional[requests.Response], float]:
        """
        Send HTTP request and measure response time.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Query parameters
            data: POST data
            
        Returns:
            Tuple of (response, response_time_ms)
        """
        start_time = time.time()
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url, 
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                logger.error(f"Unsupported method: {method}")
                return None, 0.0
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            self.stats['requests_made'] += 1
            
            return response, response_time
            
        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None, 0.0
    
    def get_baseline(self, 
                    url: str, 
                    method: str = 'GET',
                    params: Optional[Dict] = None,
                    data: Optional[Dict] = None) -> Tuple[Optional[requests.Response], float]:
        """
        Get baseline response without payloads.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Query parameters
            data: POST data
            
        Returns:
            Tuple of (response, response_time_ms)
        """
        return self.send_request(url, method, params, data)
    
    def test_parameter(self,
                      url: str,
                      parameter: str,
                      original_value: str,
                      method: str = 'GET',
                      param_type: str = 'query') -> List[SQLInjectionResult]:
        """
        Test a single parameter for SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            original_value: Original parameter value
            method: HTTP method
            param_type: 'query' or 'body'
            
        Returns:
            List of SQL injection findings
        """
        logger.info(f"Testing parameter: {parameter} = {original_value}")
        
        findings = []
        
        # Get baseline response
        if param_type == 'query':
            params = {parameter: original_value}
            baseline_response, baseline_time = self.get_baseline(
                url, method, params=params
            )
        else:  # body parameter
            data = {parameter: original_value}
            baseline_response, baseline_time = self.get_baseline(
                url, method, data=data
            )
        
        if not baseline_response:
            logger.warning(f"Baseline request failed for {parameter}")
            return findings
        
        baseline_text = baseline_response.text
        
        # Test different database types
        db_types = [
            DatabaseType.GENERIC,
            DatabaseType.MYSQL,
            DatabaseType.POSTGRESQL,
            DatabaseType.MSSQL,
            DatabaseType.ORACLE,
        ]
        
        # Test different injection types
        injection_types = [
            InjectionType.BOOLEAN,
            InjectionType.ERROR,
            InjectionType.TIME,
            InjectionType.UNION,
        ]
        
        for db_type in db_types:
            for injection_type in injection_types:
                # Get payloads for this combination
                payloads = payload_generator.get_payloads(
                    db_type, injection_type, limit=5
                )
                
                for payload in payloads:
                    # Apply delay between requests
                    time.sleep(self.delay)
                    
                    # Test the payload
                    result = self._test_payload(
                        url=url,
                        parameter=parameter,
                        original_value=original_value,
                        payload=payload,
                        injection_type=injection_type,
                        db_type=db_type,
                        method=method,
                        param_type=param_type,
                        baseline_text=baseline_text,
                        baseline_time=baseline_time
                    )
                    
                    if result and result.confidence > 0.5:
                        findings.append(result)
                        
                        # If we found a high-confidence vulnerability, move to next parameter
                        if result.confidence > 0.8:
                            logger.info(f"High confidence vulnerability found for {parameter}")
                            return findings
        
        self.stats['parameters_tested'] += 1
        
        return findings
    
    def _test_payload(self,
                     url: str,
                     parameter: str,
                     original_value: str,
                     payload: str,
                     injection_type: InjectionType,
                     db_type: DatabaseType,
                     method: str,
                     param_type: str,
                     baseline_text: str,
                     baseline_time: float) -> Optional[SQLInjectionResult]:
        """
        Test a specific payload.
        
        Returns:
            SQLInjectionResult if vulnerable, None otherwise
        """
        # Create test value with payload
        test_value = f"{original_value}{payload}"
        
        # Send request with payload
        if param_type == 'query':
            params = {parameter: test_value}
            test_response, test_time = self.send_request(
                url, method, params=params
            )
        else:
            data = {parameter: test_value}
            test_response, test_time = self.send_request(
                url, method, data=data
            )
        
        if not test_response:
            return None
        
        # Analyze response
        analysis = response_analyzer.analyze_responses(
            baseline_text,
            test_response.text,
            baseline_time,
            test_time
        )
        
        # Calculate confidence score
        confidence = self._calculate_confidence(analysis, injection_type)
        
        if confidence < 0.3:  # Low confidence, skip
            return None
        
        # Create result
        result = SQLInjectionResult(
            url=url,
            parameter=parameter,
            payload=payload,
            injection_type=injection_type.value,
            database_type=db_type.value,
            confidence=confidence,
            evidence={
                'similarity_score': analysis.similarity_score,
                'length_difference': analysis.length_difference,
                'has_sql_errors': analysis.has_sql_errors,
                'error_messages': analysis.error_messages,
                'has_time_delay': analysis.has_time_delay,
                'response_time_ms': test_time,
            },
            request={
                'method': method,
                'parameter': parameter,
                'value': test_value,
            },
            response={
                'status_code': test_response.status_code,
                'headers': dict(test_response.headers),
                'size': len(test_response.text),
            }
        )
        
        self.results.append(result)
        self.stats['vulnerabilities_found'] += 1
        
        return result
    
    def _calculate_confidence(self, 
                             analysis: ResponseAnalysis,
                             injection_type: InjectionType) -> float:
        """
        Calculate confidence score based on analysis.
        
        Args:
            analysis: Response analysis
            injection_type: Type of injection tested
            
        Returns:
            Confidence score (0-1)
        """
        confidence = 0.0
        
        # Base score for response difference
        if analysis.is_different:
            confidence += 0.2
        
        # Score for SQL errors
        if analysis.has_sql_errors:
            confidence += 0.3
        
        # Score for database errors
        if analysis.has_database_errors:
            confidence += 0.2
        
        # Score for time delays (especially for time-based injection)
        if analysis.has_time_delay:
            if injection_type == InjectionType.TIME:
                confidence += 0.4
            else:
                confidence += 0.1
        
        # Score for blank/error pages
        if analysis.has_blank_page:
            confidence += 0.1
        
        # Penalty for too similar responses
        if analysis.similarity_score > 0.95:
            confidence -= 0.1
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))
    
    def extract_parameters(self, url: str, html: Optional[str] = None) -> List[Dict]:
        """
        Extract parameters from URL and optionally HTML forms.
        
        Args:
            url: Target URL
            html: Optional HTML content for form extraction
            
        Returns:
            List of parameter dictionaries
        """
        parameters = []
        
        # Extract from URL query string
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                for value in values:
                    parameters.append({
                        'name': param,
                        'value': value,
                        'type': 'query',
                        'source': 'url'
                    })
        
        # TODO: Extract from HTML forms if provided
        
        return parameters
    
    def scan_url(self, url: str) -> List[SQLInjectionResult]:
        """
        Comprehensive SQL injection scan of a URL.
        
        Args:
            url: Target URL
            
        Returns:
            List of SQL injection findings
        """
        logger.info(f"Starting SQL injection scan: {url}")
        
        # Extract parameters
        parameters = self.extract_parameters(url)
        
        if not parameters:
            logger.info(f"No parameters found in {url}")
            return []
        
        logger.info(f"Found {len(parameters)} parameters to test")
        
        # Test each parameter
        all_findings = []
        
        for param in parameters:
            findings = self.test_parameter(
                url=url,
                parameter=param['name'],
                original_value=param['value'],
                method='GET' if param['type'] == 'query' else 'POST',
                param_type=param['type']
            )
            
            all_findings.extend(findings)
            
            # Apply delay between parameters
            time.sleep(self.delay)
        
        logger.info(f"Scan completed: {len(all_findings)} vulnerabilities found")
        
        return all_findings
    
    def export_results(self, format: str = "json") -> str:
        """
        Export scan results.
        
        Args:
            format: 'json' or 'text'
            
        Returns:
            Formatted results
        """
        if format == "json":
            import json
            data = []
            for result in self.results:
                result_dict = {
                    'url': result.url,
                    'parameter': result.parameter,
                    'payload': result.payload,
                    'injection_type': result.injection_type,
                    'database_type': result.database_type,
                    'confidence': result.confidence,
                    'evidence': result.evidence,
                }
                data.append(result_dict)
            return json.dumps(data, indent=2)
        
        elif format == "text":
            lines = []
            lines.append(f"SQL Injection Scan Results")
            lines.append(f"=" * 50)
            lines.append(f"Total vulnerabilities: {len(self.results)}")
            lines.append(f"Requests made: {self.stats['requests_made']}")
            lines.append(f"Parameters tested: {self.stats['parameters_tested']}")
            lines.append("")
            
            for i, result in enumerate(self.results, 1):
                lines.append(f"{i}. URL: {result.url}")
                lines.append(f"   Parameter: {result.parameter}")
                lines.append(f"   Payload: {result.payload}")
                lines.append(f"   Type: {result.injection_type}")
                lines.append(f"   Database: {result.database_type}")
                lines.append(f"   Confidence: {result.confidence:.2f}")
                if result.evidence.get('has_sql_errors'):
                    lines.append(f"   SQL Errors: Yes")
                if result.evidence.get('has_time_delay'):
                    lines.append(f"   Time Delay: {result.evidence['response_time_ms']:.0f}ms")
                lines.append("")
            
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")

# Test function
def test_sqli_detector():
    """Test the SQL injection detector"""
    import sys
    
    # Test URL (use a safe test site)
    test_url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    
    print(f"\nTesting SQL injection detector on: {test_url}")
    print("=" * 60)
    
    detector = SQLInjectionDetector(
        timeout=5,
        max_requests=50,
        delay=1.0
    )
    
    # Run scan
    results = detector.scan_url(test_url)
    
    # Display results
    if results:
        print(f"\nFound {len(results)} potential vulnerabilities:")
        for i, result in enumerate(results[:5]):  # Show first 5
            print(f"\n{i+1}. Parameter: {result.parameter}")
            print(f"   Payload: {result.payload[:50]}...")
            print(f"   Type: {result.injection_type}")
            print(f"   Confidence: {result.confidence:.2f}")
            if result.evidence.get('has_sql_errors'):
                print(f"   SQL Errors detected")
            if result.evidence.get('has_time_delay'):
                print(f"   Time delay: {result.evidence['response_time_ms']:.0f}ms")
    else:
        print("\nNo SQL injection vulnerabilities found")
    
    # Export results
    if results:
        print(f"\nSample export:")
        print(detector.export_results("text"))
    
    return results

if __name__ == "__main__":
    results = test_sqli_detector()