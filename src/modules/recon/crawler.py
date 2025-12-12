import requests
from bs4 import BeautifulSoup
import time
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass
import logging
import re

# Import your helpers
from src.utils.url_helpers import URLHelper
from src.utils.rate_limiter import IntelligentRateLimiter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CrawlResult:
    """Data class to store crawl results"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    links: List[str]
    forms: List[Dict]
    processing_time: float

class Crawler:
    """Advanced web crawler with rate limiting and scope control"""
    
    def __init__(
        self, 
        max_pages: int = 100, 
        delay: float = 1.0,
        stay_on_domain: bool = True,
        max_depth: int = 10,
        exclude_patterns: List[str] = None,
        use_rate_limiting: bool = True
    ):
        """
        Initialize the crawler.
        """
        self.max_pages = max_pages
        self.delay = delay
        self.stay_on_domain = stay_on_domain
        self.max_depth = max_depth
        self.exclude_patterns = exclude_patterns or []
        self.use_rate_limiting = use_rate_limiting
        
        # Initialize Rate Limiter if enabled
        if self.use_rate_limiting:
            self.rate_limiter = IntelligentRateLimiter(default_delay=delay)
        else:
            self.rate_limiter = None
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyFramework/1.0 (Research Prototype)'
        })
        
        # State management
        self.visited_urls: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = []  # (url, depth)
        self.results: List[CrawlResult] = []
        self.target_domain = None

    def should_crawl_url(self, url: str, current_depth: int) -> bool:
        """Determine if a URL should be crawled based on various criteria."""
        if url in self.visited_urls:
            return False
        if current_depth > self.max_depth:
            return False
        if not URLHelper.normalize_url(url, url):
            return False
        if self.stay_on_domain and self.target_domain:
            url_domain = URLHelper.get_domain(url)
            if self.target_domain not in url_domain: 
                return False
        for pattern in self.exclude_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        return True

    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links = []
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href', '').strip()
            if href:
                normalized = URLHelper.normalize_url(href, base_url)
                if normalized:
                    links.append(normalized)
        return links
    
    def extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.get('required') is not None
                }
                form_data['inputs'].append(input_data)
            forms.append(form_data)
        return forms
    
    def crawl_page(self, url: str) -> Optional[CrawlResult]:
        """Crawl a single page with rate limiting support"""
        try:
            logger.info(f"Crawling: {url}")
            domain = URLHelper.get_domain(url)

            # 1. Apply Rate Limiting (Wait BEFORE request)
            if self.use_rate_limiting and self.rate_limiter and domain:
                self.rate_limiter.wait_if_needed(domain)
            
            start_time = time.time()
            
            # 2. Make the Request
            response = self.session.get(
                url, 
                timeout=10,
                allow_redirects=True
            )
            
            processing_time = time.time() - start_time
            
            # 3. Record Metrics for Rate Limiter (Update logic)
            if self.use_rate_limiting and self.rate_limiter and domain:
                self.rate_limiter.record_request(
                    domain, 
                    processing_time, 
                    response.status_code
                )
            
            # Parse content
            links = []
            forms = []
            if 'text/html' in response.headers.get('content-type', '').lower():
                soup = BeautifulSoup(response.content, 'lxml')
                links = self.extract_links(soup, url)
                forms = self.extract_forms(soup)
            
            result = CrawlResult(
                url=response.url,
                status_code=response.status_code,
                content_type=response.headers.get('content-type', ''),
                content_length=len(response.content),
                links=links,
                forms=forms,
                processing_time=processing_time
            )
            
            self.results.append(result)
            return result
            
        except requests.RequestException as e:
            logger.error(f"Failed to crawl {url}: {e}")
            return None
    
    def start(self, start_url: str) -> List[CrawlResult]:
        logger.info(f"Starting crawl from: {start_url}")
        
        self.visited_urls.clear()
        self.to_visit.clear()
        self.results.clear()
        self.target_domain = URLHelper.get_domain(start_url)
        
        normalized_start = URLHelper.normalize_url(start_url, start_url)
        if normalized_start:
            self.to_visit.append((normalized_start, 0))
        
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            current_url, current_depth = self.to_visit.pop(0)
            
            if current_url in self.visited_urls:
                continue

            result = self.crawl_page(current_url)
            
            if result:
                self.visited_urls.add(current_url)
                for link in result.links:
                    if self.should_crawl_url(link, current_depth + 1):
                        self.to_visit.append((link, current_depth + 1))
            
            # Breadth-first sort
            self.to_visit.sort(key=lambda x: x[1])
            
            # Basic fallback delay if rate limiter is off
            if not self.use_rate_limiting:
                time.sleep(self.delay)
        
        logger.info(f"Crawl completed. Visited {len(self.visited_urls)} pages.")
        return self.results

if __name__ == "__main__":
    # Test with rate limiting enabled
    crawler = Crawler(max_pages=5, delay=1.0, use_rate_limiting=True)
    results = crawler.start("http://testphp.vulnweb.com")
    print(f"\nCrawled {len(results)} pages.")