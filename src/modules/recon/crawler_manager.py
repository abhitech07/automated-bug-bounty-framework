"""
Manager to coordinate between basic crawler and Playwright crawler.
"""
from typing import List, Optional
from enum import Enum
import logging

from .crawler import Crawler, CrawlResult
from .playwright_crawler import PlaywrightCrawler, JSCrawlResult
from src.utils.url_helpers import URLHelper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CrawlerType(Enum):
    BASIC = "basic"
    PLAYWRIGHT = "playwright"
    HYBRID = "hybrid"

class CrawlerManager:
    """Manages different crawler types and provides a unified interface"""
    
    def __init__(
        self,
        crawler_type: CrawlerType = CrawlerType.HYBRID,
        max_pages: int = 100,
        use_playwright_for_js: bool = True,
        detect_js_frameworks: bool = True
    ):
        self.crawler_type = crawler_type
        self.max_pages = max_pages
        self.use_playwright_for_js = use_playwright_for_js
        self.detect_js_frameworks = detect_js_frameworks
        
        # Initialize crawlers
        self.basic_crawler = None
        self.playwright_crawler = None
        
        if crawler_type in [CrawlerType.BASIC, CrawlerType.HYBRID]:
            self.basic_crawler = Crawler(max_pages=max_pages)
        
        if crawler_type in [CrawlerType.PLAYWRIGHT, CrawlerType.HYBRID]:
            self.playwright_crawler = PlaywrightCrawler(
                max_pages=max_pages // 2 if crawler_type == CrawlerType.HYBRID else max_pages,
                headless=True
            )
    
    def detect_js_usage(self, url: str) -> bool:
        """
        Simple heuristic to detect if a site likely uses JavaScript frameworks.
        In a real implementation, this would analyze responses or use Wappalyzer.
        """
        # Common JavaScript framework patterns in URLs or tech stacks
        js_frameworks = [
            'react', 'vue', 'angular', 'nextjs', 'nuxt', 'gatsby',
            'svelte', 'ember', 'backbone', 'meteor'
        ]
        
        # Check URL
        url_lower = url.lower()
        for framework in js_frameworks:
            if framework in url_lower:
                return True
        
        # TODO: Implement actual detection via HTTP headers or initial page fetch
        return False
    
    def start(self, start_url: str):
        """Start crawling with the configured crawler type"""
        logger.info(f"Starting {self.crawler_type.value} crawl on: {start_url}")
        
        if self.crawler_type == CrawlerType.BASIC:
            return self.basic_crawler.start(start_url)
        
        elif self.crawler_type == CrawlerType.PLAYWRIGHT:
            return self.playwright_crawler.start(start_url)
        
        elif self.crawler_type == CrawlerType.HYBRID:
            # Use heuristics to decide which crawler to use
            if self.use_playwright_for_js and self.detect_js_usage(start_url):
                logger.info("Detected JavaScript framework, using Playwright crawler")
                return self.playwright_crawler.start(start_url)
            else:
                logger.info("Using basic crawler")
                return self.basic_crawler.start(start_url)
        
        else:
            raise ValueError(f"Unknown crawler type: {self.crawler_type}")

# Test the manager
if __name__ == "__main__":
    # Test different crawler types
    test_urls = [
        ("http://books.toscrape.com/", CrawlerType.BASIC, "Static site"),
        # ("https://react-redux.realworld.io/", CrawlerType.PLAYWRIGHT, "React SPA"),
    ]
    
    for url, crawler_type, description in test_urls:
        print(f"\nTesting {description} with {crawler_type.value} crawler...")
        
        manager = CrawlerManager(
            crawler_type=crawler_type,
            max_pages=5
        )
        
        results = manager.start(url)
        print(f"  Crawled {len(results) if results else 0} pages")