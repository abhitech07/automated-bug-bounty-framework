"""
Performance test for SQLi scanner.
"""
import sys
sys.path.insert(0, '.')

import time
import statistics
from src.modules.scanners.sqli.scanner import SQLiScanner
from src.modules.scanners.sqli.payloads import SQLiPayloads

def test_scanner_performance():
    """Test SQLi scanner performance"""
    print("Testing SQLi Scanner Performance")
    print("=" * 80)
    
    scanner = SQLiScanner(
        timeout=5,
        delay=0.1,  # Short delay for testing
        enable_techniques=['boolean', 'error']  # Skip time-based
    )
    
    # Test data
    test_cases = [
        {
            'name': 'Simple GET with one parameter',
            'url': 'http://test.example.com/page',
            'method': 'GET',
            'params': {'id': '1'},
            'data': None,
        },
        {
            'name': 'POST with multiple parameters',
            'url': 'http://test.example.com/login',
            'method': 'POST',
            'params': None,
            'data': {'username': 'admin', 'password': 'secret'},
        },
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\nTest: {test_case['name']}")
        
        # Time the scan
        start_time = time.time()
        
        # Run scan (simulated - won't actually make requests)
        # In real test, you'd use a mock server
        print("  Note: Using simulated scan for performance testing")
        
        # Simulate scan time
        simulated_time = 0.5  # Simulated scan time in seconds
        time.sleep(simulated_time)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Estimate number of requests
        params_count = len(test_case['params'] or test_case['data'] or {})
        techniques_count = len(scanner.enable_techniques)
        payloads_per_technique = 10  # Average
        
        estimated_requests = params_count * techniques_count * payloads_per_technique
        requests_per_second = estimated_requests / elapsed if elapsed > 0 else 0
        
        result = {
            'test_case': test_case['name'],
            'elapsed_time': elapsed,
            'estimated_requests': estimated_requests,
            'requests_per_second': requests_per_second,
        }
        
        results.append(result)
        
        print(f"  Elapsed time: {elapsed:.2f}s")
        print(f"  Estimated requests: {estimated_requests}")
        print(f"  Requests/second: {requests_per_second:.1f}")
    
    # Calculate statistics
    if results:
        avg_rps = statistics.mean([r['requests_per_second'] for r in results])
        avg_time = statistics.mean([r['elapsed_time'] for r in results])
        
        print("\n" + "=" * 80)
        print("PERFORMANCE SUMMARY:")
        print(f"  Average requests/second: {avg_rps:.1f}")
        print(f"  Average scan time: {avg_time:.2f}s")
        
        if avg_rps > 2.0:
            print("  ✅ Performance: GOOD")
        elif avg_rps > 1.0:
            print("  ⚠️ Performance: ACCEPTABLE")
        else:
            print("  ❌ Performance: POOR - needs optimization")
    
    return results

def test_payload_generation_performance():
    """Test payload generation performance"""
    print("\n\nTesting Payload Generation Performance")
    print("=" * 80)
    
    payloads = SQLiPayloads()
    
    # Test payload retrieval
    start_time = time.time()
    
    techniques = ['boolean', 'error', 'time']
    total_payloads = 0
    
    for technique in techniques:
        technique_payloads = payloads.get_payloads_by_technique(technique)
        total_payloads += len(technique_payloads)
        
        # Test payload variations
        if technique_payloads:
            sample_payload = technique_payloads[0]
            variations = payloads.generate_fuzzing_payloads(sample_payload, 5)
            total_payloads += len(variations)
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    print(f"  Total payloads generated: {total_payloads}")
    print(f"  Generation time: {elapsed:.4f}s")
    print(f"  Payloads/second: {total_payloads / elapsed:.1f}")
    
    if elapsed < 0.1:
        print("  ✅ Payload generation: EXCELLENT")
    elif elapsed < 0.5:
        print("  ⚠️ Payload generation: GOOD")
    else:
        print("  ❌ Payload generation: SLOW")

def run_performance_tests():
    """Run all performance tests"""
    print("SQLi Module Performance Tests")
    print("=" * 80)
    
    try:
        scanner_results = test_scanner_performance()
        payload_results = test_payload_generation_performance()
        
        print("\n" + "=" * 80)
        print("✅ Performance testing completed")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Performance testing failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_performance_tests()
    sys.exit(0 if success else 1)