"""
Advanced analysis engine combining all SQLi detection techniques.
"""
from typing import List, Dict, Optional, Tuple
import time
from dataclasses import dataclass, asdict
import statistics
import logging

from .response_comparator import ResponseComparator, ComparisonResult
from .false_positive_filter import FalsePositiveFilter
from .response_analyzer import SQLiResponseAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    """Result of advanced SQLi analysis"""
    is_vulnerable: bool
    technique: str  # 'boolean', 'error', 'time', 'union', 'blind'
    confidence: float
    database_type: Optional[str]
    evidence: Dict[str, any]
    details: Dict[str, any]
    false_positive_risk: float

class AdvancedAnalysisEngine:
    """
    Advanced engine for SQL injection analysis.
    """
    
    def __init__(
        self,
        boolean_threshold: float = 0.7,
        error_confidence_threshold: float = 0.6,
        time_delay_threshold: float = 2.0,
        enable_fp_filter: bool = True
    ):
        """
        Initialize the analysis engine.
        
        Args:
            boolean_threshold: Threshold for boolean-based detection
            error_confidence_threshold: Threshold for error-based detection
            time_delay_threshold: Threshold for time-based detection (seconds)
            enable_fp_filter: Enable false positive filtering
        """
        self.boolean_threshold = boolean_threshold
        self.error_threshold = error_confidence_threshold
        self.time_threshold = time_delay_threshold
        
        self.comparator = ResponseComparator()
        self.fp_filter = FalsePositiveFilter() if enable_fp_filter else None
        self.response_analyzer = SQLiResponseAnalyzer()
        
        # Statistics
        self.stats = {
            'total_analyses': 0,
            'detections': 0,
            'false_positives_filtered': 0,
            'technique_counts': {
                'boolean': 0,
                'error': 0,
                'time': 0,
                'union': 0,
            }
        }
    
    def analyze_boolean_based(
        self,
        baseline_response: str,
        baseline_status: int,
        true_response: str,
        true_status: int,
        false_response: str,
        false_status: int,
        payload_pair: Tuple[str, str]
    ) -> AnalysisResult:
        """
        Analyze boolean-based SQL injection.
        
        Args:
            baseline_response: Original response
            baseline_status: Original status code
            true_response: Response with TRUE condition payload
            true_status: TRUE response status code
            false_response: Response with FALSE condition payload
            false_status: FALSE response status code
            payload_pair: (true_payload, false_payload)
            
        Returns:
            AnalysisResult object
        """
        self.stats['total_analyses'] += 1
        
        # Compare TRUE vs FALSE responses
        true_false_comparison = self.comparator.compare_responses(
            true_response, true_status,
            false_response, false_status
        )
        
        # Compare each with baseline
        true_baseline_comparison = self.comparator.compare_responses(
            true_response, true_status,
            baseline_response, baseline_status
        )
        
        false_baseline_comparison = self.comparator.compare_responses(
            false_response, false_status,
            baseline_response, baseline_status
        )
        
        # Calculate vulnerability confidence
        confidence = 0.0
        is_vulnerable = False
        
        # Strong indicator: TRUE and FALSE responses are different
        if true_false_comparison.is_significantly_different:
            confidence = true_false_comparison.confidence
            
            # Boost confidence if one response is similar to baseline but other is not
            if (true_baseline_comparison.similarity_score > 0.9 and 
                false_baseline_comparison.similarity_score < 0.7):
                confidence = min(confidence + 0.2, 0.95)
            elif (false_baseline_comparison.similarity_score > 0.9 and 
                  true_baseline_comparison.similarity_score < 0.7):
                confidence = min(confidence + 0.2, 0.95)
        
        # Check for SQL indicators
        true_indicators = self.comparator.detect_sql_indicators(true_response)
        false_indicators = self.comparator.detect_sql_indicators(false_response)
        
        if true_indicators['sql_errors'] or false_indicators['sql_errors']:
            confidence = min(confidence + 0.25, 0.95)
        
        # Determine if vulnerable
        is_vulnerable = confidence >= self.boolean_threshold
        
        if is_vulnerable:
            self.stats['detections'] += 1
            self.stats['technique_counts']['boolean'] += 1
        
        # Determine database type from indicators
        db_type = None
        if true_indicators['database_errors']:
            db_type = true_indicators['database_errors'][0]
        elif false_indicators['database_errors']:
            db_type = false_indicators['database_errors'][0]
        
        # Calculate false positive risk
        fp_risk = self.calculate_false_positive_risk(
            baseline_response, true_response, false_response
        )
        
        # Prepare evidence
        evidence = {
            'true_false_comparison': asdict(true_false_comparison),
            'true_baseline_comparison': asdict(true_baseline_comparison),
            'false_baseline_comparison': asdict(false_baseline_comparison),
            'true_indicators': true_indicators,
            'false_indicators': false_indicators,
            'payload_pair': payload_pair,
        }
        
        details = {
            'comparison_scores': {
                'true_vs_false': true_false_comparison.similarity_score,
                'true_vs_baseline': true_baseline_comparison.similarity_score,
                'false_vs_baseline': false_baseline_comparison.similarity_score,
            },
            'status_codes': {
                'baseline': baseline_status,
                'true': true_status,
                'false': false_status,
            },
            'response_lengths': {
                'baseline': len(baseline_response),
                'true': len(true_response),
                'false': len(false_response),
            },
        }
        
        return AnalysisResult(
            is_vulnerable=is_vulnerable,
            technique='boolean',
            confidence=confidence,
            database_type=db_type,
            evidence=evidence,
            details=details,
            false_positive_risk=fp_risk
        )
    
    def analyze_error_based(
        self,
        baseline_response: str,
        baseline_status: int,
        injected_response: str,
        injected_status: int,
        payload: str
    ) -> AnalysisResult:
        """
        Analyze error-based SQL injection.
        
        Args:
            baseline_response: Original response
            baseline_status: Original status code
            injected_response: Response with error payload
            injected_status: Injected response status code
            payload: The payload used
            
        Returns:
            AnalysisResult object
        """
        self.stats['total_analyses'] += 1
        
        # Use the response analyzer for SQL error detection
        is_vulnerable, confidence, errors = self.response_analyzer.is_error_based_vulnerable(
            injected_response
        )
        
        # Compare with baseline
        comparison = self.comparator.compare_responses(
            injected_response, injected_status,
            baseline_response, baseline_status
        )
        
        # Boost confidence if response is significantly different from baseline
        if comparison.is_significantly_different:
            confidence = min(confidence + 0.15, 0.95)
        
        # Detect SQL indicators
        indicators = self.comparator.detect_sql_indicators(injected_response)
        
        if indicators['sql_errors']:
            confidence = min(confidence + 0.1, 0.95)
        
        # Determine database type
        db_type = None
        if errors:
            # Get the most specific database type
            specific_dbs = [db for db in errors.keys() if db != 'generic']
            db_type = specific_dbs[0] if specific_dbs else 'generic'
        
        if is_vulnerable and confidence >= self.error_threshold:
            self.stats['detections'] += 1
            self.stats['technique_counts']['error'] += 1
        else:
            is_vulnerable = False
        
        # Calculate false positive risk
        fp_risk = self.calculate_false_positive_risk(
            baseline_response, injected_response
        )
        
        # Prepare evidence
        evidence = {
            'detected_errors': errors,
            'comparison_with_baseline': asdict(comparison),
            'sql_indicators': indicators,
            'payload': payload,
        }
        
        details = {
            'error_count': sum(len(e) for e in errors.values()),
            'database_errors': list(errors.keys()),
            'status_code_difference': injected_status != baseline_status,
            'response_length_difference': abs(len(injected_response) - len(baseline_response)),
        }
        
        return AnalysisResult(
            is_vulnerable=is_vulnerable,
            technique='error',
            confidence=confidence,
            database_type=db_type,
            evidence=evidence,
            details=details,
            false_positive_risk=fp_risk
        )
    
    def analyze_time_based(
        self,
        baseline_time: float,
        injected_time: float,
        confirmation_time: float,
        payload: str,
        expected_delay: int
    ) -> AnalysisResult:
        """
        Analyze time-based SQL injection.
        
        Args:
            baseline_time: Baseline response time
            injected_time: Injected response time
            confirmation_time: Confirmation (double delay) response time
            payload: The payload used
            expected_delay: Expected delay in payload
            
        Returns:
            AnalysisResult object
        """
        self.stats['total_analyses'] += 1
        
        is_vulnerable = False
        confidence = 0.0
        db_type = None
        
        # Check if injected time exceeds threshold
        time_difference = injected_time - baseline_time
        
        if time_difference >= self.time_threshold:
            confidence = min(time_difference / (expected_delay * 2), 0.9)
            
            # Check confirmation (should be roughly double)
            confirmation_difference = confirmation_time - baseline_time
            expected_confirmation = expected_delay * 2
            
            if abs(confirmation_difference - expected_confirmation) < 2.0:  # Within 2 seconds
                confidence = min(confidence + 0.2, 0.95)
                is_vulnerable = True
        
        # Determine database type from payload
        if 'SLEEP' in payload.upper():
            db_type = 'mysql'
        elif 'pg_sleep' in payload.lower():
            db_type = 'postgresql'
        elif 'WAITFOR' in payload.upper():
            db_type = 'mssql'
        elif 'DBMS_LOCK.SLEEP' in payload.upper():
            db_type = 'oracle'
        
        if is_vulnerable:
            self.stats['detections'] += 1
            self.stats['technique_counts']['time'] += 1
        
        # Time-based has lower false positive risk (hard to fake delays)
        fp_risk = 0.1 if is_vulnerable else 0.8
        
        # Prepare evidence
        evidence = {
            'timing_data': {
                'baseline_time': baseline_time,
                'injected_time': injected_time,
                'confirmation_time': confirmation_time,
                'time_difference': time_difference,
                'confirmation_difference': confirmation_difference,
            },
            'payload': payload,
            'expected_delay': expected_delay,
        }
        
        details = {
            'time_exceeded_threshold': time_difference >= self.time_threshold,
            'confirmation_matched': abs(confirmation_difference - (expected_delay * 2)) < 2.0,
            'timing_consistency': abs((confirmation_difference / 2) - time_difference) < 1.0,
        }
        
        return AnalysisResult(
            is_vulnerable=is_vulnerable,
            technique='time',
            confidence=confidence,
            database_type=db_type,
            evidence=evidence,
            details=details,
            false_positive_risk=fp_risk
        )
    
    def calculate_false_positive_risk(
        self,
        *responses: str
    ) -> float:
        """
        Calculate false positive risk based on response characteristics.
        
        Args:
            *responses: Response strings to analyze
            
        Returns:
            False positive risk (0.0 to 1.0)
        """
        if not responses:
            return 0.5
        
        risks = []
        
        for response in responses:
            risk = 0.0
            
            # Short responses are risky
            if len(response) < 100:
                risk += 0.3
            
            # Check for common false positive patterns
            fp_patterns = [
                'Internal Server Error',
                'Not Found',
                'Error 500',
                'Apache',
                'nginx',
                'JSON',
                'XML',
            ]
            
            for pattern in fp_patterns:
                if pattern.lower() in response.lower():
                    risk += 0.1
            
            # Generic error messages
            if 'error' in response.lower() and 'sql' not in response.lower():
                risk += 0.2
            
            risks.append(min(risk, 0.8))
        
        # Return average risk
        return statistics.mean(risks) if risks else 0.5
    
    def apply_false_positive_filter(
        self,
        analysis_results: List[AnalysisResult],
        responses: Dict[str, str]
    ) -> List[AnalysisResult]:
        """
        Apply false positive filtering to analysis results.
        
        Args:
            analysis_results: List of analysis results
            responses: Dictionary of response contents
            
        Returns:
            Filtered analysis results
        """
        if not self.fp_filter:
            return analysis_results
        
        filtered_results = []
        
        for result in analysis_results:
            # Convert to dict for filtering
            result_dict = asdict(result)
            
            # Get response content for this result
            response_key = result.evidence.get('payload', 'unknown')
            response_content = responses.get(response_key, '')
            
            # Analyze for false positives
            fp_analysis = self.fp_filter.analyze_response(
                response_content,
                result.details.get('status_code', 200)
            )
            
            # Only keep if not a likely false positive
            if not fp_analysis['is_likely_false_positive']:
                # Update false positive risk
                result.false_positive_risk = max(
                    result.false_positive_risk,
                    fp_analysis['confidence']
                )
                filtered_results.append(result)
            else:
                self.stats['false_positives_filtered'] += 1
                logger.info(f"Filtered out potential false positive: {fp_analysis['matched_rules']}")
        
        return filtered_results
    
    def get_statistics(self) -> Dict[str, any]:
        """Get analysis statistics"""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset analysis statistics"""
        self.stats = {
            'total_analyses': 0,
            'detections': 0,
            'false_positives_filtered': 0,
            'technique_counts': {
                'boolean': 0,
                'error': 0,
                'time': 0,
                'union': 0,
            }
        }

# Test function
def test_analysis_engine():
    """Test the advanced analysis engine"""
    engine = AdvancedAnalysisEngine()
    
    print("Testing Advanced Analysis Engine")
    print("=" * 80)
    
    # Test 1: Boolean-based analysis
    print("\n1. Testing Boolean-based Analysis:")
    
    bool_result = engine.analyze_boolean_based(
        baseline_response="Welcome to the site",
        baseline_status=200,
        true_response="Welcome admin",
        true_status=200,
        false_response="Access denied",
        false_status=200,
        payload_pair=("' AND '1'='1", "' AND '1'='2")
    )
    
    print(f"   Vulnerable: {bool_result.is_vulnerable}")
    print(f"   Confidence: {bool_result.confidence:.2f}")
    print(f"   DB Type: {bool_result.database_type}")
    print(f"   FP Risk: {bool_result.false_positive_risk:.2f}")
    
    # Test 2: Error-based analysis
    print("\n2. Testing Error-based Analysis:")
    
    error_result = engine.analyze_error_based(
        baseline_response="Welcome to the site",
        baseline_status=200,
        injected_response="SQL syntax error near SELECT",
        injected_status=200,
        payload="'"
    )
    
    print(f"   Vulnerable: {error_result.is_vulnerable}")
    print(f"   Confidence: {error_result.confidence:.2f}")
    print(f"   DB Type: {error_result.database_type}")
    print(f"   FP Risk: {error_result.false_positive_risk:.2f}")
    
    # Test 3: Time-based analysis
    print("\n3. Testing Time-based Analysis:")
    
    time_result = engine.analyze_time_based(
        baseline_time=1.0,
        injected_time=6.5,
        confirmation_time=11.2,
        payload="' AND SLEEP(5)--",
        expected_delay=5
    )
    
    print(f"   Vulnerable: {time_result.is_vulnerable}")
    print(f"   Confidence: {time_result.confidence:.2f}")
    print(f"   DB Type: {time_result.database_type}")
    print(f"   FP Risk: {time_result.false_positive_risk:.2f}")
    
    # Print statistics
    print("\nEngine Statistics:")
    stats = engine.get_statistics()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for subkey, subvalue in value.items():
                print(f"     {subkey}: {subvalue}")
        else:
            print(f"   {key}: {value}")

if __name__ == "__main__":
    test_analysis_engine()