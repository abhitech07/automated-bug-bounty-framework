"""
Integration test for SQLi analysis engine.
"""
import sys
sys.path.insert(0, '.')

from src.modules.scanners.sqli.analysis_engine import AdvancedAnalysisEngine
from src.modules.scanners.sqli.response_comparator import ResponseComparator
from src.modules.scanners.sqli.false_positive_filter import FalsePositiveFilter

def test_integration():
    """Test the integrated SQLi analysis system"""
    print("Testing Integrated SQLi Analysis System")
    print("=" * 80)
    
    # Create components
    comparator = ResponseComparator()
    fp_filter = FalsePositiveFilter()
    analysis_engine = AdvancedAnalysisEngine()
    
    # Test data
    test_cases = [
        {
            'name': 'Boolean SQLi - Different responses',
            'baseline': 'Welcome to our site',
            'true_response': 'Welcome admin user',
            'false_response': 'Access denied',
            'expected_vulnerable': True,
        },
        {
            'name': 'Boolean SQLi - Similar responses',
            'baseline': 'Welcome to our site',
            'true_response': 'Welcome to our site',
            'false_response': 'Welcome to our site',
            'expected_vulnerable': False,
        },
        {
            'name': 'Error-based SQLi',
            'baseline': 'Product page',
            'injected_response': 'SQL syntax error near SELECT',
            'expected_vulnerable': True,
        },
        {
            'name': 'False Positive - Generic error',
            'baseline': 'Normal page',
            'injected_response': 'Internal Server Error',
            'expected_vulnerable': False,
        },
    ]
    
    results = []
    
    for test in test_cases:
        print(f"\nTest: {test['name']}")
        
        if 'true_response' in test:
            # Boolean test
            result = analysis_engine.analyze_boolean_based(
                baseline_response=test['baseline'],
                baseline_status=200,
                true_response=test['true_response'],
                true_status=200,
                false_response=test['false_response'],
                false_status=200,
                payload_pair=("' AND '1'='1", "' AND '1'='2")
            )
            
            vulnerable = result.is_vulnerable
            confidence = result.confidence
            
        else:
            # Error-based test
            result = analysis_engine.analyze_error_based(
                baseline_response=test['baseline'],
                baseline_status=200,
                injected_response=test['injected_response'],
                injected_status=200,
                payload="'"
            )
            
            vulnerable = result.is_vulnerable
            confidence = result.confidence
            
            # Check false positive filter
            fp_analysis = fp_filter.analyze_response(test['injected_response'], 200)
            if fp_analysis['is_likely_false_positive']:
                vulnerable = False
        
        # Compare with expected
        passed = vulnerable == test['expected_vulnerable']
        
        print(f"  Result: {'VULNERABLE' if vulnerable else 'SAFE'}")
        print(f"  Confidence: {confidence:.2f}")
        print(f"  Expected: {'VULNERABLE' if test['expected_vulnerable'] else 'SAFE'}")
        print(f"  Status: {'✓ PASS' if passed else '✗ FAIL'}")
        
        results.append(passed)
    
    # Print summary
    print("\n" + "=" * 80)
    print(f"SUMMARY: {sum(results)}/{len(results)} tests passed")
    
    if all(results):
        print("✅ All integration tests passed!")
    else:
        print("⚠️ Some tests failed. Review the implementation.")
    
    return all(results)

if __name__ == "__main__":
    success = test_integration()
    sys.exit(0 if success else 1)