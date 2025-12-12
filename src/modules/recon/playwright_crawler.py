import asyncio
from typing import List, Dict, Set, Optional
import logging
from dataclasses import dataclass
from urllib.parse import urljoin
import time

from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from src.utils.url_helpers import URLHelper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class JSCrawlResult:
    """Data class for JavaScript crawl results"""
    url: str
    title: str
    html: str
    links: List[str]
    forms: List[Dict]
    cookies: List[Dict]
    console_logs: List[str]
    network_requests: List[Dict]
    screenshot_path: Optional[str] = None
    processing_time: float = 0.0

class PlaywrightCrawler:
    """Crawler for JavaScript-rendered websites using Playwright"""
    
    def __init__(
        self,
        max_pages: int = 50,
        headless: bool = True,
        timeout: int = 30000,
        wait_after_load: int = 2000
    ):
        """
        Initialize the Playwright crawler.
        
        Args:
            max_pages: Maximum pages to crawl
            headless: Run browser in headless mode
            timeout: Page load timeout in milliseconds
            wait_after_load: Wait time after page load in milliseconds
        """
        self.max_pages = max_pages
        self.headless = headless
        self.timeout = timeout
        self.wait_after_load = wait_after_load
        
        self.visited_urls: Set[str] = set()
        self.to_visit: List[str] = []
        self.results: List[JSCrawlResult] = []
        
        # Playwright objects
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
    
    async def setup_browser(self):
        """Set up the Playwright browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )
        self.context = await self.browser.new_context(
            viewport={'width': 1280, 'height': 800},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
    
    async def close_browser(self):
        """Close the browser and cleanup"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def crawl_page(self, page: Page, url: str) -> Optional[JSCrawlResult]:
        """Crawl a single page with Playwright"""
        try:
            logger.info(f"[Playwright] Crawling: {url}")
            start_time = time.time()
            
            # Setup event listeners for this page
            console_logs = []
            network_requests = []
            
            def on_console(msg):
                console_logs.append({
                    'type': msg.type,
                    'text': msg.text,
                    'url': msg.location.get('url', ''),
                    'timestamp': time.time()
                })
            
            def on_request(request):
                network_requests.append({
                    'url': request.url,
                    'method': request.method,
                    'resource_type': request.resource_type,
                    'timestamp': time.time()
                })
            
            page.on('console', on_console)
            page.on('request', on_request)
            
            # Navigate to the page
            await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            
            # Wait for additional time for JavaScript to execute
            await asyncio.sleep(self.wait_after_load / 1000)
            
            # Extract page information
            title = await page.title()
            html = await page.content()
            
            # Extract all links
            links = await page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    links.push(a.href);
                });
                return links;
            }''')
            
            # Extract forms and their inputs
            forms = await page.evaluate('''() => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const formData = {
                        action: form.action,
                        method: form.method || 'GET',
                        inputs: []
                    };
                    
                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        formData.inputs.push({
                            type: input.type || input.tagName.toLowerCase(),
                            name: input.name,
                            value: input.value,
                            required: input.required
                        });
                    });
                    
                    forms.push(formData);
                });
                return forms;
            }''')
            
            # Get cookies
            cookies = await self.context.cookies()
            
            # Take screenshot (optional)
            screenshot_path = None
            if not self.headless:  # Only take screenshots in headed mode for demo
                screenshot_path = f"screenshots/{URLHelper.get_domain(url)}_{int(time.time())}.png"
                await page.screenshot(path=screenshot_path, full_page=True)
            
            processing_time = time.time() - start_time
            
            result = JSCrawlResult(
                url=url,
                title=title,
                html=html,
                links=links,
                forms=forms,
                cookies=cookies,
                console_logs=console_logs,
                network_requests=network_requests,
                screenshot_path=screenshot_path,
                processing_time=processing_time
            )
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to crawl {url} with Playwright: {e}")
            return None
    
    async def start_async(self, start_url: str) -> List[JSCrawlResult]:
        """Asynchronous start method for Playwright crawler"""
        logger.info(f"Starting Playwright crawl from: {start_url}")
        
        # Setup
        await self.setup_browser()
        
        # Reset state
        self.visited_urls.clear()
        self.to_visit.clear()
        self.results.clear()
        
        # Add starting URL
        normalized_start = URLHelper.normalize_url(start_url, start_url)
        if normalized_start:
            self.to_visit.append(normalized_start)
        
        # Main crawling loop
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            current_url = self.to_visit.pop(0)
            
            if current_url in self.visited_urls:
                continue
            
            # Create a new page for each URL
            page = await self.context.new_page()
            
            # Crawl the page
            result = await self.crawl_page(page, current_url)
            
            # Close the page
            await page.close()
            
            if result:
                self.visited_urls.add(current_url)
                
                # Add new links to queue
                for link in result.links:
                    normalized_link = URLHelper.normalize_url(link, current_url)
                    if (normalized_link and 
                        normalized_link not in self.visited_urls and 
                        normalized_link not in self.to_visit and
                        len(self.visited_urls) + len(self.to_visit) < self.max_pages):
                        self.to_visit.append(normalized_link)
        
        # Cleanup
        await self.close_browser()
        
        logger.info(f"Playwright crawl completed. Visited {len(self.visited_urls)} pages.")
        return self.results
    
    def start(self, start_url: str) -> List[JSCrawlResult]:
        """Synchronous wrapper for the async crawler"""
        return asyncio.run(self.start_async(start_url))

# Test function
async def test_playwright_crawler_async():
    """Test the Playwright crawler"""
    crawler = PlaywrightCrawler(max_pages=3, headless=False)  # Headful for demo
    results = await crawler.start_async("https://react-redux.realworld.io/")
    
    print(f"\nPlaywright Crawl Results ({len(results)} pages):")
    for i, result in enumerate(results):
        print(f"\n{i+1}. {result.url}")
        print(f"   Title: {result.title[:50]}...")
        print(f"   Links found: {len(result.links)}")
        print(f"   Forms found: {len(result.forms)}")
        print(f"   Network requests: {len(result.network_requests)}")
    
    return results

def test_playwright_crawler():
    """Synchronous test function"""
    return asyncio.run(test_playwright_crawler_async())

if __name__ == "__main__":
    test_playwright_crawler()