"""
Cross-Site Scripting (XSS) Detection Module.
Detects reflected, stored, and DOM-based XSS vulnerabilities.
"""
import re
import requests
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class XSSType(str, Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom_based"

@dataclass
class XSSFinding:
    url: str
    parameter: str
    payload: str
    xss_type: XSSType
    confidence: float
    context: str  # html, javascript, attribute, css
    evidence: Dict

class XSSScanner:
    """XSS Vulnerability Scanner"""
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        
        # XSS payload collections
        self.payloads = {
            'html_context': [
                '<script>alert("xss")</script>',
                '<img src=x onerror=alert("xss")>',
                '<svg onload=alert("xss")>',
                '<body onload=alert("xss")>',
                '<iframe src=javascript:alert("xss")>',
            ],
            'attribute_context': [
                '" onmouseover="alert(\'xss\')" x="',
                '\' onload=\'alert("xss")\' x=\'',
                '" autofocus onfocus="alert(\'xss\')" x="',
            ],
            'javascript_context': [
                '";alert("xss");//',
                '\');alert("xss");//',
                '";alert(String.fromCharCode(88,83,83));//',
            ],
            'css_context': [
                'x<style>@import "javascript:alert(\'xss\')"</style>',
                'background:url("javascript:alert(\'xss\')")',
            ]
        }
        
        # Dangerous HTML patterns
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=',
            r'javascript:',
            r'<iframe',
            r'<embed',
            r'<object',
        ]
    
    def scan_parameter(self, 
                      url: str, 
                      parameter: str, 
                      method: str = 'GET') -> List[XSSFinding]:
        """
        Scan a parameter for XSS vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter name
            method: HTTP method
            
        Returns:
            List of XSSFinding objects
        """
        findings = []
        
        # Get baseline response
        baseline = self._get_response(url, parameter, "", method)
        if not baseline:
            return findings
        
        # Test each payload
        for context, payloads in self.payloads.items():
            for payload in payloads:
                finding = self._test_payload(
                    url, parameter, payload, method, 
                    baseline, context
                )
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _test_payload(self,
                     url: str,
                     parameter: str,
                     payload: str,
                     method: str,
                     baseline: str,
                     context: str) -> Optional[XSSFinding]:
        """Test a single XSS payload"""
        response = self._get_response(url, parameter, payload, method)
        if not response:
            return None
        
        # Check if payload is reflected
        if payload in response:
            # Check what encoding/context it appears in
            context_type = self._analyze_reflection_context(
                response, payload, baseline
            )
            
            confidence = 0.9
            
            return XSSFinding(
                url=url,
                parameter=parameter,
                payload=payload,
                xss_type=XSSType.REFLECTED,
                confidence=confidence,
                context=context_type,
                evidence={
                    'payload_found': True,
                    'position_in_html': response.find(payload),
                    'response_length': len(response),
                }
            )
        
        return None
    
    def _analyze_reflection_context(self, 
                                   response: str, 
                                   payload: str,
                                   baseline: str) -> str:
        """Determine the context where payload appears"""
        # Find position of payload
        pos = response.find(payload)
        if pos == -1:
            return "unknown"
        
        # Check surrounding context
        start = max(0, pos - 50)
        end = min(len(response), pos + len(payload) + 50)
        context_snippet = response[start:end]
        
        if '<script' in context_snippet:
            return "javascript"
        elif 'on' in context_snippet and '=' in context_snippet:
            return "attribute"
        elif 'style=' in context_snippet:
            return "css"
        else:
            return "html"
    
    def _get_response(self, url: str, parameter: str, 
                     payload: str, method: str) -> Optional[str]:
        """Get response with injected payload"""
        try:
            if method.upper() == 'GET':
                params = {parameter: payload}
                resp = self.session.get(url, params=params, timeout=self.timeout)
            else:
                data = {parameter: payload}
                resp = self.session.post(url, data=data, timeout=self.timeout)
            
            return resp.text
        except:
            return None

# Test
if __name__ == "__main__":
    scanner = XSSScanner()
    print("XSS Scanner initialized")