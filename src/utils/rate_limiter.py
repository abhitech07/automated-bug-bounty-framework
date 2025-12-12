"""
Intelligent rate limiting for polite crawling.
"""
import time
from typing import Dict, Optional
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class RateLimitStats:
    domain: str
    requests_made: int
    last_request_time: datetime
    average_response_time: float
    crawl_delay_respected: bool = True

class IntelligentRateLimiter:
    """Intelligent rate limiter that adapts based on server responses"""
    
    def __init__(
        self,
        default_delay: float = 1.0,
        max_requests_per_minute: int = 60,
        respect_robots_txt: bool = True,
        adaptive_delays: bool = True
    ):
        self.default_delay = default_delay
        self.max_requests_per_minute = max_requests_per_minute
        self.respect_robots_txt = respect_robots_txt
        self.adaptive_delays = adaptive_delays
        
        # Track requests per domain
        self.domain_stats: Dict[str, RateLimitStats] = {}
        self.request_timestamps: Dict[str, list] = defaultdict(list)
        
        # Robots.txt crawl delays
        self.robots_delays: Dict[str, float] = {}
    
    def set_robots_delay(self, domain: str, delay: float):
        """Set crawl delay from robots.txt"""
        self.robots_delays[domain] = delay
        logger.info(f"Set robots.txt crawl delay for {domain}: {delay}s")
    
    def get_delay_for_domain(self, domain: str) -> float:
        """Get appropriate delay for a domain"""
        # Start with default delay
        delay = self.default_delay
        
        # Apply robots.txt delay if available and respected
        if self.respect_robots_txt and domain in self.robots_delays:
            robots_delay = self.robots_delays[domain]
            if robots_delay > delay:
                delay = robots_delay
        
        # Adaptive delay based on server response time
        if self.adaptive_delays and domain in self.domain_stats:
            stats = self.domain_stats[domain]
            
            # If server is responding slowly, increase delay
            if stats.average_response_time > 2.0:  # More than 2 seconds
                delay = max(delay, 3.0)
            elif stats.average_response_time > 5.0:  # More than 5 seconds
                delay = max(delay, 5.0)
            
            # If we're getting rate limited (429), increase delay significantly
            if not stats.crawl_delay_respected:
                delay = max(delay, 10.0)
        
        return delay
    
    def can_make_request(self, domain: str) -> bool:
        """Check if we can make a request to this domain"""
        now = datetime.now()
        
        # Clean old timestamps (older than 1 minute)
        if domain in self.request_timestamps:
            one_minute_ago = now - timedelta(minutes=1)
            self.request_timestamps[domain] = [
                ts for ts in self.request_timestamps[domain] if ts > one_minute_ago
            ]
        
        # Check if we've exceeded rate limit
        if len(self.request_timestamps.get(domain, [])) >= self.max_requests_per_minute:
            return False
        
        return True
    
    def record_request(
        self,
        domain: str,
        response_time: float,
        status_code: int
    ):
        """Record a request for rate limiting"""
        now = datetime.now()
        
        # Record timestamp
        self.request_timestamps[domain].append(now)
        
        # Update domain stats
        if domain not in self.domain_stats:
            self.domain_stats[domain] = RateLimitStats(
                domain=domain,
                requests_made=1,
                last_request_time=now,
                average_response_time=response_time
            )
        else:
            stats = self.domain_stats[domain]
            stats.requests_made += 1
            stats.last_request_time = now
            
            # Update average response time (moving average)
            stats.average_response_time = (
                stats.average_response_time * 0.7 + response_time * 0.3
            )
            
            # Check if we're being rate limited
            if status_code == 429:  # Too Many Requests
                stats.crawl_delay_respected = False
            elif status_code < 400:
                stats.crawl_delay_respected = True
    
    def wait_if_needed(self, domain: str):
        """Wait for the appropriate delay before next request"""
        if not self.can_make_request(domain):
            # Calculate how long to wait
            now = datetime.now()
            timestamps = self.request_timestamps.get(domain, [])
            
            if timestamps:
                oldest = min(timestamps)
                wait_time = 60 - (now - oldest).total_seconds()
                if wait_time > 0:
                    logger.info(f"Rate limit reached for {domain}. Waiting {wait_time:.1f}s")
                    time.sleep(wait_time)
        
        # Get delay for this domain
        delay = self.get_delay_for_domain(domain)
        
        # Wait the delay
        if delay > 0:
            time.sleep(delay)
    
    def get_stats(self) -> Dict[str, RateLimitStats]:
        """Get current statistics"""
        return self.domain_stats.copy()

# Test the rate limiter
if __name__ == "__main__":
    limiter = IntelligentRateLimiter(
        default_delay=1.0,
        max_requests_per_minute=30,
        respect_robots_txt=True,
        adaptive_delays=True
    )
    
    # Simulate some requests
    test_domains = ['example.com', 'test.com']
    
    for i in range(10):
        for domain in test_domains:
            print(f"\nRequest {i+1} to {domain}")
            
            # Check if we can make request
            if limiter.can_make_request(domain):
                print(f"  Can make request")
                
                # Simulate request
                response_time = 0.5 + (i * 0.1)  # Increasing response time
                status_code = 200 if i < 8 else 429  # Simulate rate limit
                
                # Record request
                limiter.record_request(domain, response_time, status_code)
                
                # Wait for next request
                limiter.wait_if_needed(domain)
            else:
                print(f"  Rate limited, waiting...")
                limiter.wait_if_needed(domain)
    
    # Print stats
    print("\nFinal Statistics:")
    for domain, stats in limiter.get_stats().items():
        print(f"\n{domain}:")
        print(f"  Requests made: {stats.requests_made}")
        print(f"  Avg response time: {stats.average_response_time:.2f}s")
        print(f"  Crawl delay respected: {stats.crawl_delay_respected}")