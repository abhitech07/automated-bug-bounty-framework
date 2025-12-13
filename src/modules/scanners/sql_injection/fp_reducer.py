"""
False positive reduction for SQL injection findings.
"""
from typing import List, Dict, Set
import re
from dataclasses import dataclass
import logging
from .scanner import SQLiFinding

logger = logging.getLogger(__name__)

@dataclass
class ReductionRule:
    """Rule for reducing false positives"""
    name: str
    description: str
    condition: callable
    action: str  # 'discard', 'reduce_confidence', 'flag'
    severity: str  # 'high', 'medium', 'low'

class FalsePositiveReducer:
    """Reduce false positives in SQL injection findings"""
    
    def __init__(self):
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> List[ReductionRule]:
        """Initialize false positive reduction rules."""
        rules = [
            # Rule 1: Same response for true/false
            ReductionRule(
                name="identical_responses",
                description="True and false responses are identical",
                condition=self._identical_responses,
                action="discard",
                severity="high"
            ),
            
            # Rule 2: Response too similar to baseline
            ReductionRule(
                name="similar_to_baseline",
                description="Response too similar to baseline (no change)",
                condition=self._too_similar_to_baseline,
                action="reduce_confidence",
                severity="medium"
            ),
            
            # Rule 3: Common false positive patterns
            ReductionRule(
                name="common_fp_pattern",
                description="Matches common false positive pattern",
                condition=self._common_false_positive_pattern,
                action="flag",
                severity="low"
            ),
            
            # Rule 4: Error in both true and false
            ReductionRule(
                name="error_in_both",
                description="SQL error appears in both true and false responses",
                condition=self._error_in_both_responses,
                action="reduce_confidence",
                severity="medium"
            ),
            
            # Rule 5: Response indicates WAF/blocking
            ReductionRule(
                name="waf_detected",
                description="Response indicates WAF or blocking mechanism",
                condition=self._waf_detected,
                action="flag",
                severity="low"
            ),
        ]
        
        return rules
    
    def _identical_responses(self, finding: SQLiFinding) -> bool:
        """Check if true and false responses are identical."""
        evidence = finding.evidence
        
        if 'true_response' in evidence and 'false_response' in evidence:
            true_resp = evidence['true_response']
            false_resp = evidence['false_response']
            
            # Compare key attributes
            if (true_resp.get('status_code') == false_resp.get('status_code') and
                true_resp.get('content_length') == false_resp.get('content_length')):
                
                # If they also have similarity score, check it
                if 'true_false_similarity' in evidence:
                    return evidence['true_false_similarity'] > 0.95
                return True
        
        return False
    
    def _too_similar_to_baseline(self, finding: SQLiFinding) -> bool:
        """Check if response is too similar to baseline."""
        evidence = finding.evidence
        
        similarity_keys = [
            'similarity_with_baseline',
            'true_baseline_similarity',
            'false_baseline_similarity'
        ]
        
        for key in similarity_keys:
            if key in evidence:
                similarity = evidence[key]
                if isinstance(similarity, dict) and 'overall' in similarity:
                    similarity = similarity['overall']
                
                if similarity > 0.9:  # 90% similar
                    return True
        
        return False
    
    def _common_false_positive_pattern(self, finding: SQLiFinding) -> bool:
        """Check for common false positive patterns."""
        # Common patterns that often cause false positives
        common_fp_patterns = [
            # Login forms that respond differently based on input
            r"(login|signin|auth|password)",
            # Search forms
            r"(search|query|find|lookup)",
            # Pagination
            r"(page|offset|limit|start)",
            # Sort parameters
            r"(sort|order|by)",
        ]
        
        url_lower = finding.url.lower()
        param_lower = finding.parameter.lower()
        
        for pattern in common_fp_patterns:
            if (re.search(pattern, url_lower) or 
                re.search(pattern, param_lower)):
                return True
        
        return False
    
    def _error_in_both_responses(self, finding: SQLiFinding) -> bool:
        """Check if SQL error appears in both responses."""
        evidence = finding.evidence
        
        # Check for error count in both responses
        if 'error_count' in evidence:
            error_count = evidence['error_count']
            if isinstance(error_count, dict):
                # Check if errors in both true and false
                true_errors = error_count.get('true', 0)
                false_errors = error_count.get('false', 0)
                
                if true_errors > 0 and false_errors > 0:
                    return True
        
        return False
    
    def _waf_detected(self, finding: SQLiFinding) -> bool:
        """Check if WAF or blocking mechanism is detected."""
        waf_indicators = [
            r"cloudflare",
            r"akamai",
            r"imperva",
            r"fortinet",
            r"barracuda",
            r"mod_security",
            r"403 forbidden",
            r"access denied",
            r"your request has been blocked",
            r"security violation detected",
        ]
        
        # Check in evidence
        evidence_str = str(finding.evidence).lower()
        
        for indicator in waf_indicators:
            if re.search(indicator, evidence_str):
                return True
        
        return False
    
    def reduce_false_positives(self, findings: List[SQLiFinding]) -> List[SQLiFinding]:
        """
        Apply false positive reduction rules to findings.
        
        Args:
            findings: List of SQLiFinding objects
            
        Returns:
            Filtered list of findings
        """
        filtered_findings = []
        
        for finding in findings:
            original_confidence = finding.confidence
            flags = []
            should_discard = False
            
            # Apply each rule
            for rule in self.rules:
                if rule.condition(finding):
                    logger.debug(f"Rule '{rule.name}' triggered for finding {finding.url}")
                    
                    if rule.action == 'discard':
                        should_discard = True
                        logger.info(f"Discarding finding due to rule: {rule.name}")
                        break
                    
                    elif rule.action == 'reduce_confidence':
                        # Reduce confidence based on rule severity
                        reduction = {
                            'high': 0.4,
                            'medium': 0.2,
                            'low': 0.1
                        }.get(rule.severity, 0.1)
                        
                        finding.confidence = max(0.1, finding.confidence - reduction)
                    
                    elif rule.action == 'flag':
                        flags.append(rule.name)
            
            if not should_discard:
                # Add flags to evidence
                if flags:
                    if 'flags' not in finding.evidence:
                        finding.evidence['flags'] = []
                    finding.evidence['flags'].extend(flags)
                
                # Only keep if confidence is still reasonable
                if finding.confidence >= 0.3:
                    filtered_findings.append(finding)
                else:
                    logger.info(f"Discarding finding with low confidence: {finding.confidence:.2f}")
        
        logger.info(f"False positive reduction: {len(findings)} -> {len(filtered_findings)} findings")
        return filtered_findings

# Test function
def test_fp_reducer():
    """Test the false positive reducer"""
    reducer = FalsePositiveReducer()
    
    # Create a test finding
    test_finding = SQLiFinding(
        url="http://example.com/login.php",
        parameter="username",
        payload="' OR '1'='1",
        technique="boolean",
        confidence=0.8,
        evidence={
            'true_response': {'status_code': 200, 'content_length': 1500},
            'false_response': {'status_code': 200, 'content_length': 1500},
            'true_false_similarity': 0.98,
            'similarity_with_baseline': 0.95
        }
    )
    
    print("Testing false positive reducer...")
    results = reducer.reduce_false_positives([test_finding])
    
    print(f"Input findings: 1")
    print(f"Output findings: {len(results)}")
    
    if results:
        print(f"Final confidence: {results[0].confidence:.2f}")
        if 'flags' in results[0].evidence:
            print(f"Flags: {results[0].evidence['flags']}")
    
    return reducer

if __name__ == "__main__":
    test_fp_reducer()