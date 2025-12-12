"""
Advanced discovery features for reconnaissance.
"""
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
import time
import re
from typing import List, Dict, Optional, Set
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SitemapEntry:
    url: str
    lastmod: Optional[str] = None
    changefreq: Optional[str] = None
    priority: Optional[float] = None

@dataclass
class RobotsTxtInfo:
    is_present: bool
    sitemaps: List[str]
    disallowed_paths: List[str]
    crawl_delay: Optional[float] = None
    user_agent: str = '*'

class AdvancedDiscovery:
    """Advanced discovery features for reconnaissance"""
    
    def __init__(self, user_agent: str = None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_robots_txt(self, base_url: str) -> RobotsTxtInfo:
        """
        Check and parse robots.txt file.
        
        Args:
            base_url: Base URL of the website
            
        Returns:
            RobotsTxtInfo object with parsed information
        """
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, timeout=10)
            
            if response.status_code != 200:
                return RobotsTxtInfo(
                    is_present=False,
                    sitemaps=[],
                    disallowed_paths=[]
                )
            
            content = response.text
            lines = content.split('\n')
            
            sitemaps = []
            disallowed_paths = []
            crawl_delay = None
            current_ua = '*'
            
            for line in lines:
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Parse directive
                if ':' in line:
                    directive, value = line.split(':', 1)
                    directive = directive.strip().lower()
                    value = value.strip()
                    
                    if directive == 'user-agent':
                        current_ua = value
                    
                    elif directive == 'sitemap' and current_ua == '*':
                        sitemaps.append(value)
                    
                    elif directive == 'disallow' and current_ua == '*':
                        if value:
                            disallowed_paths.append(value)
                    
                    elif directive == 'crawl-delay' and current_ua == '*':
                        try:
                            crawl_delay = float(value)
                        except:
                            pass
            
            return RobotsTxtInfo(
                is_present=True,
                sitemaps=sitemaps,
                disallowed_paths=disallowed_paths,
                crawl_delay=crawl_delay
            )
            
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch robots.txt: {e}")
            return RobotsTxtInfo(
                is_present=False,
                sitemaps=[],
                disallowed_paths=[]
            )
    
    def parse_sitemap(self, sitemap_url: str) -> List[SitemapEntry]:
        """
        Parse sitemap.xml file.
        
        Args:
            sitemap_url: URL of the sitemap
            
        Returns:
            List of SitemapEntry objects
        """
        entries = []
        
        try:
            response = self.session.get(sitemap_url, timeout=10)
            
            if response.status_code != 200:
                return entries
            
            # Parse XML
            root = ET.fromstring(response.content)
            
            # Check if it's a sitemap index
            if root.tag.endswith('sitemapindex'):
                # Parse nested sitemaps
                for sitemap in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                    loc_elem = sitemap.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc_elem is not None and loc_elem.text:
                        # Recursively parse nested sitemap
                        nested_entries = self.parse_sitemap(loc_elem.text)
                        entries.extend(nested_entries)
            
            # Parse regular sitemap
            elif root.tag.endswith('urlset'):
                for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                    entry = SitemapEntry(url='')
                    
                    # Get URL
                    loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc_elem is not None and loc_elem.text:
                        entry.url = loc_elem.text
                    
                    # Get last modification date
                    lastmod_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod')
                    if lastmod_elem is not None and lastmod_elem.text:
                        entry.lastmod = lastmod_elem.text
                    
                    # Get change frequency
                    changefreq_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}changefreq')
                    if changefreq_elem is not None and changefreq_elem.text:
                        entry.changefreq = changefreq_elem.text
                    
                    # Get priority
                    priority_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}priority')
                    if priority_elem is not None and priority_elem.text:
                        try:
                            entry.priority = float(priority_elem.text)
                        except:
                            pass
                    
                    if entry.url:
                        entries.append(entry)
            
            logger.info(f"Parsed {len(entries)} URLs from sitemap: {sitemap_url}")
            
        except Exception as e:
            logger.error(f"Failed to parse sitemap {sitemap_url}: {e}")
        
        return entries
    
    def discover_from_common_paths(self, base_url: str) -> List[str]:
        """
        Discover URLs by checking common paths and files.
        
        Args:
            base_url: Base URL to check
            
        Returns:
            List of discovered URLs
        """
        common_paths = [
            # Administration
            '/admin', '/admin/login', '/admin/dashboard', '/wp-admin', '/administrator',
            '/login', '/signin', '/auth', '/oauth',
            '/register', '/signup', '/join',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
            '/.git/HEAD', '/.env', '/config.json', '/package.json',
            '/composer.json', '/yarn.lock', '/package-lock.json',
            
            # API endpoints
            '/api', '/api/v1', '/graphql', '/rest', '/soap',
            
            # Documentation
            '/docs', '/documentation', '/help', '/api-docs', '/swagger',
            
            # Common directories
            '/assets', '/static', '/public', '/uploads', '/images',
            '/css', '/js', '/fonts', '/vendor', '/node_modules',
            
            # Backup files
            '/backup', '/backups', '/old', '/temp', '/tmp',
            
            # Configuration
            '/config', '/settings', '/configuration',
            
            # Debug
            '/debug', '/phpinfo', '/test', '/demo',
            
            # Search
            '/search', '/find', '/query',
        ]
        
        discovered = []
        
        for path in common_paths:
            test_url = urljoin(base_url, path)
            
            try:
                response = self.session.head(test_url, timeout=5, allow_redirects=True)
                
                # Check if URL exists (2xx or 3xx status)
                if response.status_code < 400:
                    discovered.append(test_url)
                    logger.debug(f"Discovered: {test_url} ({response.status_code})")
                
            except requests.RequestException:
                continue
            
            # Be polite
            time.sleep(0.1)
        
        return discovered
    
    def find_technology_footprints(self, url: str) -> Dict[str, List[str]]:
        """
        Identify technologies used by the website.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary of technology categories and detected technologies
        """
        footprints = {
            'web_frameworks': [],
            'javascript_frameworks': [],
            'web_servers': [],
            'programming_languages': [],
            'databases': [],
            'cms': [],
            'analytics': [],
            'caching': []
        }
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check headers
            headers = response.headers
            
            # Server header
            server = headers.get('Server', '').lower()
            if server:
                if 'apache' in server:
                    footprints['web_servers'].append('Apache')
                elif 'nginx' in server:
                    footprints['web_servers'].append('Nginx')
                elif 'iis' in server:
                    footprints['web_servers'].append('IIS')
            
            # X-Powered-By header
            powered_by = headers.get('X-Powered-By', '').lower()
            if powered_by:
                if 'php' in powered_by:
                    footprints['programming_languages'].append('PHP')
                elif 'asp.net' in powered_by:
                    footprints['web_frameworks'].append('ASP.NET')
            
            # Check response content
            content = response.text.lower()
            
            # WordPress detection
            if 'wp-content' in content or 'wp-includes' in content:
                footprints['cms'].append('WordPress')
            
            # React detection
            if 'react' in content or 'react-dom' in content:
                footprints['javascript_frameworks'].append('React')
            
            # Vue.js detection
            if 'vue' in content or 'vue.js' in content:
                footprints['javascript_frameworks'].append('Vue.js')
            
            # Angular detection
            if 'angular' in content:
                footprints['javascript_frameworks'].append('Angular')
            
            # jQuery detection
            if 'jquery' in content:
                footprints['javascript_frameworks'].append('jQuery')
            
            # Google Analytics
            if 'google-analytics' in content or 'ga(' in content:
                footprints['analytics'].append('Google Analytics')
            
            # Check cookies
            cookies = response.cookies
            for cookie in cookies:
                cookie_name = cookie.name.lower()
                if 'wordpress' in cookie_name:
                    footprints['cms'].append('WordPress')
                elif 'drupal' in cookie_name:
                    footprints['cms'].append('Drupal')
                elif 'joomla' in cookie_name:
                    footprints['cms'].append('Joomla')
            
            # Check for common patterns in URLs
            if '/wp-json/' in response.url:
                footprints['cms'].append('WordPress')
        
        except requests.RequestException as e:
            logger.warning(f"Failed to analyze technologies for {url}: {e}")
        
        return footprints

# Test the discovery module
if __name__ == "__main__":
    discovery = AdvancedDiscovery()
    
    # Test URLs
    test_urls = [
        "https://github.com",
        "http://books.toscrape.com/",
    ]
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        print("-" * 50)
        
        # Check robots.txt
        robots_info = discovery.check_robots_txt(url)
        print(f"Robots.txt present: {robots_info.is_present}")
        if robots_info.sitemaps:
            print(f"Sitemaps found: {len(robots_info.sitemaps)}")
            for sitemap in robots_info.sitemaps[:3]:  # Show first 3
                print(f"  - {sitemap}")
        
        # Discover common paths
        discovered = discovery.discover_from_common_paths(url)
        print(f"Common paths discovered: {len(discovered)}")
        for path in discovered[:5]:  # Show first 5
            print(f"  - {path}")
        
        # Find technology footprints
        tech = discovery.find_technology_footprints(url)
        print(f"Technologies detected:")
        for category, technologies in tech.items():
            if technologies:
                print(f"  {category}: {', '.join(technologies)}")