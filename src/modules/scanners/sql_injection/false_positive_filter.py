"""
Intelligent false positive filter for SQLi detection.
"""
import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
import hashlib

@dataclass
class FilterRule:
    """Rule for filtering false positives"""
    name: str
    condition: str  # 'contains', 'regex', 'length', 'ratio'
    pattern: str
    severity: str  # 'warning', 'high', 'critical'
    description: str

class FalsePositiveFilter:
    """
    Filter to reduce false positives in SQLi detection.
    """
    
    def __init__(self):
        self.rules = self.load_default_rules()
        self.filtered_patterns = set()
        
    def load_default_rules(self) -> List[FilterRule]:
        """Load default false positive filtering rules"""
        return [
            # Common error messages that aren't SQLi
            FilterRule(
                name="generic_error_page",
                condition="contains",
                pattern="Internal Server Error",
                severity="high",
                description="Generic server error, not SQLi specific"
            ),
            FilterRule(
                name="framework_error",
                condition="contains",
                pattern="FrameworkException",
                severity="high",
                description="Framework error, not SQLi"
            ),
            FilterRule(
                name="file_not_found",
                condition="contains",
                pattern="404 Not Found",
                severity="warning",
                description="Page not found error"
            ),
            
            # Common patterns that cause false positives
            FilterRule(
                name="json_response",
                condition="regex",
                pattern=r'^\s*\{.*\}\s*$',
                severity="high",
                description="JSON response, unlikely to contain SQL errors"
            ),
            FilterRule(
                name="xml_response",
                condition="regex",
                pattern=r'^\s*<\?xml',
                severity="high",
                description="XML response"
            ),
            
            # Length-based rules
            FilterRule(
                name="too_short",
                condition="length",
                pattern="<100",
                severity="warning",
                description="Response too short for reliable analysis"
            ),
            FilterRule(
                name="too_long",
                condition="length",
                pattern=">1000000",
                severity="warning",
                description="Response too long, may be binary"
            ),
            
            # Common false positive SQL patterns
            FilterRule(
                name="sql_in_text",
                condition="contains",
                pattern="SQL Server",
                severity="warning",
                description="'SQL' mentioned in text, not an error"
            ),
            FilterRule(
                name="mysql_in_text",
                condition="contains",
                pattern="MySQL Database",
                severity="warning",
                description="'MySQL' mentioned in text, not an error"
            ),
            
            # Common web server messages
            FilterRule(
                name="apache_error",
                condition="regex",
                pattern=r'Apache.*Error',
                severity="high",
                description="Apache generic error"
            ),
            FilterRule(
                name="nginx_error",
                condition="regex",
                pattern=r'nginx.*error',
                severity="high",
                description="Nginx generic error"
            ),
        ]
    
    def check_rule(self, content: str, rule: FilterRule) -> bool:
        """Check if content matches a rule"""
        if rule.condition == "contains":
            return rule.pattern.lower() in content.lower()
        
        elif rule.condition == "regex":
            return bool(re.search(rule.pattern, content, re.IGNORECASE | re.DOTALL))
        
        elif rule.condition == "length":
            content_length = len(content)
            if rule.pattern.startswith("<"):
                max_len = int(rule.pattern[1:])
                return content_length < max_len
            elif rule.pattern.startswith(">"):
                min_len = int(rule.pattern[1:])
                return content_length > min_len
        
        return False
    
    def analyze_response(self, content: str, status_code: int) -> Dict[str, any]:
        """
        Analyze a response for false positive indicators.
        
        Args:
            content: Response content
            status_code: HTTP status code
            
        Returns:
            Analysis results
        """
        analysis = {
            'is_likely_false_positive': False,
            'matched_rules': [],
            'confidence': 0.0,
            'reasons': [],
        }
        
        matched_rules = []
        
        for rule in self.rules:
            if self.check_rule(content, rule):
                matched_rules.append({
                    'name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description,
                })
        
        if matched_rules:
            analysis['matched_rules'] = matched_rules
            
            # Calculate confidence based on matched rules
            severity_weights = {
                'warning': 0.3,
                'high': 0.7,
                'critical': 0.9,
            }
            
            max_severity = max([r['severity'] for r in matched_rules])
            analysis['confidence'] = severity_weights.get(max_severity, 0.5)
            
            # Check status code patterns
            if status_code >= 500:
                analysis['confidence'] = min(analysis['confidence'] + 0.2, 0.95)
                analysis['reasons'].append(f"Server error status: {status_code}")
            
            if len(matched_rules) > 1:
                analysis['confidence'] = min(analysis['confidence'] + 0.1 * (len(matched_rules) - 1), 0.95)
            
            analysis['is_likely_false_positive'] = analysis['confidence'] > 0.6
        
        return analysis
    
    def filter_findings(
        self,
        findings: List[Dict],
        original_response: str,
        injected_responses: Dict[str, str]
    ) -> List[Dict]:
        """
        Filter SQLi findings to remove likely false positives.
        
        Args:
            findings: List of SQLi finding dictionaries
            original_response: Original (non-injected) response
            injected_responses: Dict of parameter->response for injected requests
            
        Returns:
            Filtered findings
        """
        filtered = []
        
        for finding in findings:
            # Get the response for this finding
            param = finding.get('parameter', '')
            response_key = f"{finding.get('url')}_{param}_{finding.get('payload_hash', '')}"
            
            if response_key in injected_responses:
                response_content = injected_responses[response_key]
                
                # Analyze for false positives
                analysis = self.analyze_response(
                    response_content,
                    finding.get('status_code', 200)
                )
                
                # Only keep if not a likely false positive
                if not analysis['is_likely_false_positive']:
                    # Add analysis to finding
                    finding['false_positive_analysis'] = analysis
                    filtered.append(finding)
                else:
                    print(f"Filtered out finding: {analysis['matched_rules']}")
            else:
                # Keep finding if we can't analyze it
                filtered.append(finding)
        
        return filtered
    
    def learn_from_feedback(
        self,
        finding: Dict,
        is_false_positive: bool,
        feedback_reason: str = None
    ):
        """
        Learn from manual feedback to improve filtering.
        
        Args:
            finding: The finding that was reviewed
            is_false_positive: Whether it was a false positive
            feedback_reason: Reason for the feedback
        """
        if is_false_positive:
            # Extract patterns from the finding to avoid in future
            content = finding.get('response_content', '')
            
            # Create a signature of this false positive
            signature = hashlib.md5(content.encode()).hexdigest()[:16]
            self.filtered_patterns.add(signature)
            
            # If we have a specific reason, try to create a rule
            if feedback_reason and 'pattern' in feedback_reason.lower():
                # Simple pattern extraction (in real implementation, use ML)
                pass
    
    def get_stats(self) -> Dict[str, any]:
        """Get filter statistics"""
        return {
            'total_rules': len(self.rules),
            'filtered_patterns': len(self.filtered_patterns),
            'rule_categories': {
                'contains': len([r for r in self.rules if r.condition == 'contains']),
                'regex': len([r for r in self.rules if r.condition == 'regex']),
                'length': len([r for r in self.rules if r.condition == 'length']),
            }
        }

# Test function
def test_false_positive_filter():
    """Test the false positive filter"""
    filter_engine = FalsePositiveFilter()
    
    test_responses = [
        {
            'content': 'Internal Server Error\nSomething went wrong',
            'status': 500,
            'expected': True,  # Should be filtered
        },
        {
            'content': 'SQL syntax error near SELECT * FROM users',
            'status': 200,
            'expected': False,  # Should NOT be filtered
        },
        {
            'content': '{"error": "not found"}',
            'status': 404,
            'expected': True,  # Should be filtered (JSON)
        },
        {
            'content': 'Welcome to our MySQL Database documentation',
            'status': 200,
            'expected': True,  # Should be filtered (MySQL in text)
        },
        {
            'content': 'Error: Division by zero in SQL query',
            'status': 200,
            'expected': False,  # Should NOT be filtered (real SQL error)
        },
    ]
    
    print("Testing False Positive Filter:")
    print("=" * 80)
    
    for i, test in enumerate(test_responses):
        analysis = filter_engine.analyze_response(test['content'], test['status'])
        
        print(f"\nTest {i+1}:")
        print(f"  Content preview: {test['content'][:50]}...")
        print(f"  Status: {test['status']}")
        print(f"  Is FP: {analysis['is_likely_false_positive']}")
        print(f"  Confidence: {analysis['confidence']:.2f}")
        
        if analysis['matched_rules']:
            print(f"  Matched rules: {[r['name'] for r in analysis['matched_rules']]}")
        
        # Check if filter worked as expected
        if analysis['is_likely_false_positive'] == test['expected']:
            print(f"  ✓ PASS: Filter worked as expected")
        else:
            print(f"  ✗ FAIL: Filter did not work as expected")

if __name__ == "__main__":
    test_false_positive_filter()