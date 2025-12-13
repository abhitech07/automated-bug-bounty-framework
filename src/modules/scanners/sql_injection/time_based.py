"""
Time-based SQL injection detection.
"""
import time
import statistics
from typing import List, Dict, Optional, Tuple
import logging
from dataclasses import dataclass
import re

from .payloads import SQLiPayloads

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TimeBasedResult:
    """Results from time-based SQL injection testing"""
    parameter: str
    payload: str
    is_vulnerable: bool
    confidence: float
    response_times: List[float]
    baseline_time: float
    database_type: Optional[str] = None
    evidence: Optional[Dict] = None

class TimeBasedSQLiTester:
    """Time-based SQL injection tester"""
    
    def __init__(self, payloads: SQLiPayloads = None):
        self.payloads = payloads or SQLiPayloads()
        
        # Time-based payload delays (in seconds)
        self.delays = {
            'quick': 3,     # Quick test
            'normal': 5,    # Normal test
            'confirm': 10   # Confirmation test
        }
        
        # Network latency allowance (seconds)
        self.latency_allowance = 1.0
        
        # Statistical significance threshold
        self.significance_threshold = 2.0  # Standard deviations
    
    def test_parameter(self, url: str, parameter: str, method: str,
                      get_params: Dict, post_data: Dict, session) -> List[TimeBasedResult]:
        """
        Test a parameter for time-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            get_params: GET parameters
            post_data: POST data
            session: Requests session
            
        Returns:
            List of TimeBasedResult objects
        """
        results = []
        
        # Get baseline response time (multiple samples for accuracy)
        baseline_times = self._get_baseline_times(
            url, parameter, method, get_params, post_data, session
        )
        
        if not baseline_times:
            logger.warning(f"Could not establish baseline for {parameter}")
            return results
        
        baseline_avg = statistics.mean(baseline_times)
        baseline_std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
        
        logger.info(f"Baseline for {parameter}: avg={baseline_avg:.2f}s, std={baseline_std:.2f}")
        
        # Test time-based payloads for each database
        for db_type in ['mysql', 'postgresql', 'mssql', 'oracle']:
            db_results = self._test_database_payloads(
                url, parameter, method, get_params, post_data, session,
                db_type, baseline_avg, baseline_std
            )
            results.extend(db_results)
        
        return results
    
    def _get_baseline_times(self, url: str, parameter: str, method: str,
                           get_params: Dict, post_data: Dict, session,
                           num_samples: int = 3) -> List[float]:
        """
        Get baseline response times for a parameter.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            get_params: GET parameters
            post_data: POST data
            session: Requests session
            num_samples: Number of baseline samples
            
        Returns:
            List of response times in seconds
        """
        baseline_times = []
        
        # Use a neutral payload for baseline
        neutral_payloads = ['1', 'test', 'abc123']
        
        for i in range(num_samples):
            payload = neutral_payloads[i % len(neutral_payloads)]
            
            try:
                start_time = time.time()
                
                if method.upper() == 'GET':
                    params = get_params.copy() if get_params else {}
                    params[parameter] = payload
                    response = session.get(url, params=params, timeout=30)
                else:
                    data = post_data.copy() if post_data else {}
                    data[parameter] = payload
                    response = session.post(url, data=data, timeout=30)
                
                elapsed = time.time() - start_time
                baseline_times.append(elapsed)
                
                logger.debug(f"Baseline sample {i+1}: {elapsed:.2f}s")
                
                # Small delay between baseline requests
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Baseline request failed: {e}")
        
        return baseline_times
    
    def _test_database_payloads(self, url: str, parameter: str, method: str,
                               get_params: Dict, post_data: Dict, session,
                               db_type: str, baseline_avg: float, 
                               baseline_std: float) -> List[TimeBasedResult]:
        """
        Test time-based payloads for a specific database type.
        
        Returns:
            List of TimeBasedResult objects
        """
        results = []
        
        # Get time-based payloads for this database
        time_payloads = self.payloads.get_payloads_by_technique('time', db_type)
        
        if not time_payloads:
            return results
        
        # Test each payload
        for payload in time_payloads[:3]:  # Limit to 3 payloads per DB type
            logger.info(f"Testing time-based ({db_type}): {payload}")
            
            # Extract expected delay from payload
            expected_delay = self._extract_expected_delay(payload)
            
            if expected_delay is None:
                expected_delay = self.delays['normal']
            
            # Send the payload multiple times for reliability
            response_times = []
            is_vulnerable = False
            confidence = 0.0
            
            for attempt in range(2):  # Two attempts for confirmation
                try:
                    start_time = time.time()
                    
                    if method.upper() == 'GET':
                        params = get_params.copy() if get_params else {}
                        params[parameter] = payload
                        response = session.get(url, params=params, timeout=expected_delay + 10)
                    else:
                        data = post_data.copy() if post_data else {}
                        data[parameter] = payload
                        response = session.post(url, data=data, timeout=expected_delay + 10)
                    
                    elapsed = time.time() - start_time
                    response_times.append(elapsed)
                    
                    logger.debug(f"Attempt {attempt+1}: {elapsed:.2f}s (expected: {expected_delay}s)")
                    
                    # Check if response time indicates vulnerability
                    if elapsed >= expected_delay - self.latency_allowance:
                        is_vulnerable = True
                        
                        # Calculate confidence based on how close to expected delay
                        time_diff = abs(elapsed - expected_delay)
                        if time_diff <= 1.0:
                            confidence = max(confidence, 0.9)
                        elif time_diff <= 2.0:
                            confidence = max(confidence, 0.7)
                        else:
                            confidence = max(confidence, 0.5)
                    
                    # Delay between attempts
                    if attempt == 0:
                        time.sleep(2)
                    
                except Exception as e:
                    # Timeout might indicate vulnerability
                    if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                        response_times.append(expected_delay + 5)  # Assume timeout at expected delay + 5
                        is_vulnerable = True
                        confidence = max(confidence, 0.6)
                    logger.debug(f"Request attempt {attempt+1} failed: {e}")
            
            # Statistical analysis if we have multiple samples
            if len(response_times) >= 2:
                avg_time = statistics.mean(response_times)
                
                # Check if average time is significantly above baseline
                if avg_time > baseline_avg + (self.significance_threshold * baseline_std):
                    is_vulnerable = True
                    
                    # Adjust confidence based on statistical significance
                    sig_multiple = (avg_time - baseline_avg) / baseline_std if baseline_std > 0 else 0
                    stat_confidence = min(0.3 + (sig_multiple * 0.1), 0.8)
                    confidence = max(confidence, stat_confidence)
            
            if is_vulnerable and confidence > 0.5:
                # Perform confirmation test with different delay
                confirmed = self._confirm_vulnerability(
                    url, parameter, method, get_params, post_data, session,
                    payload, db_type, baseline_avg
                )
                
                if confirmed:
                    confidence = min(confidence + 0.1, 0.95)
                
                result = TimeBasedResult(
                    parameter=parameter,
                    payload=payload,
                    is_vulnerable=True,
                    confidence=confidence,
                    response_times=response_times,
                    baseline_time=baseline_avg,
                    database_type=db_type,
                    evidence={
                        'expected_delay': expected_delay,
                        'average_response_time': statistics.mean(response_times) if response_times else 0,
                        'baseline_average': baseline_avg,
                        'baseline_std': baseline_std,
                        'confirmed': confirmed
                    }
                )
                results.append(result)
                
                logger.info(f"✅ Potential time-based SQLi found in {parameter} ({db_type})")
                logger.info(f"   Confidence: {confidence:.2f}, Avg delay: {statistics.mean(response_times):.2f}s")
        
        return results
    
    def _extract_expected_delay(self, payload: str) -> Optional[float]:
        """Extract expected delay from time-based payload."""
        # Look for numbers in the payload
        delay_patterns = [
            r'SLEEP\((\d+(?:\.\d+)?)\)',
            r'pg_sleep\((\d+(?:\.\d+)?)\)',
            r"DELAY '00:00:(\d+(?:\.\d+)?)'",
            r'RECEIVE_MESSAGE\(.*?,(\d+(?:\.\d+)?)\)',
            r'BENCHMARK\(.*?,.*?\)',  # Benchmarks don't have explicit delay
        ]
        
        for pattern in delay_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except (ValueError, IndexError):
                    pass
        
        # Default delays for common functions
        if 'SLEEP' in payload.upper():
            return 5.0
        elif 'pg_sleep' in payload.lower():
            return 5.0
        elif 'DELAY' in payload.upper():
            return 5.0
        elif 'BENCHMARK' in payload.upper():
            return 3.0
        
        return None
    
    def _confirm_vulnerability(self, url: str, parameter: str, method: str,
                              get_params: Dict, post_data: Dict, session,
                              original_payload: str, db_type: str, 
                              baseline_avg: float) -> bool:
        """
        Confirm time-based vulnerability with a different delay.
        
        Args:
            original_payload: The payload that triggered the vulnerability
            db_type: Database type
            
        Returns:
            True if confirmed, False otherwise
        """
        try:
            # Create a payload with different delay
            if db_type == 'mysql':
                confirm_payload = original_payload.replace('5', '8')  # Change delay from 5 to 8
            elif db_type == 'postgresql':
                confirm_payload = original_payload.replace('5', '8')
            elif db_type == 'mssql':
                confirm_payload = original_payload.replace('00:00:05', '00:00:08')
            elif db_type == 'oracle':
                confirm_payload = original_payload.replace('5', '8')
            else:
                confirm_payload = original_payload
            
            # Send confirmation request
            start_time = time.time()
            
            if method.upper() == 'GET':
                params = get_params.copy() if get_params else {}
                params[parameter] = confirm_payload
                response = session.get(url, params=params, timeout=30)
            else:
                data = post_data.copy() if post_data else {}
                data[parameter] = confirm_payload
                response = session.post(url, data=data, timeout=30)
            
            elapsed = time.time() - start_time
            
            # Check if response time increased proportionally
            original_delay = self._extract_expected_delay(original_payload) or 5
            confirm_delay = self._extract_expected_delay(confirm_payload) or 8
            
            expected_ratio = confirm_delay / original_delay
            actual_ratio = elapsed / baseline_avg if baseline_avg > 0 else 0
            
            # Allow some variance
            ratio_diff = abs(actual_ratio - expected_ratio)
            
            logger.debug(f"Confirmation: original={original_delay}s, confirm={confirm_delay}s, "
                        f"actual={elapsed:.2f}s, ratio_diff={ratio_diff:.2f}")
            
            return ratio_diff < 2.0  # Allow up to 2x difference
            
        except Exception as e:
            logger.error(f"Confirmation test failed: {e}")
            return False

# Test function
def test_time_based_tester():
    """Test the time-based tester"""
    tester = TimeBasedSQLiTester()
    
    print("Testing time-based payload delay extraction:")
    
    test_payloads = [
        "' AND SLEEP(5)--",
        "' AND pg_sleep(3)--",
        "' WAITFOR DELAY '00:00:05'--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),10)--",
        "' AND BENCHMARK(1000000,MD5('A'))--"
    ]
    
    for payload in test_payloads:
        delay = tester._extract_expected_delay(payload)
        print(f"  {payload[:40]:<40} -> {delay}s")
    
    return tester

if __name__ == "__main__":
    test_time_based_tester()