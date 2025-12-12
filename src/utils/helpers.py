from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from typing import Set, List, Optional, Tuple
import re
import tldextract

class URLHelper:
    """Utility class for URL manipulation and analysis"""
    
    @staticmethod
    def normalize_url(url: str, base_url: str = None) -> Optional[str]:
        """
        Normalize a URL to its canonical form.
        
        Args:
            url: The URL to normalize
            base_url: Base URL for resolving relative URLs
            
        Returns:
            Normalized URL or None if invalid
        """
        try:
            # If base_url is provided and url is relative, join them
            if base_url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Normalize components
            # - Lowercase scheme and host
            # - Remove default ports (80 for http, 443 for https)
            # - Remove fragment
            # - Sort query parameters
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            
            # Remove port if it's default
            if ':' in netloc:
                host, port = netloc.split(':', 1)
                if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
                    netloc = host
            
            # Sort query parameters
            query = ''
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                # Sort by parameter name
                sorted_params = {k: params[k] for k in sorted(params)}
                query = urlencode(sorted_params, doseq=True)
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                netloc,
                parsed.path.rstrip('/') or '/',  # Empty path becomes '/'
                parsed.params,
                query,
                ''  # Remove fragment
            ))
            
            return normalized
            
        except Exception as e:
            return None
    
    @staticmethod
    def get_domain(url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            extracted = tldextract.extract(url)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            return None
        except:
            return None
    
    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs belong to the same domain"""
        domain1 = URLHelper.get_domain(url1)
        domain2 = URLHelper.get_domain(url2)
        return domain1 is not None and domain1 == domain2
    
    @staticmethod
    def filter_urls(
        urls: List[str], 
        target_domain: str = None,
        exclude_patterns: List[str] = None
    ) -> List[str]:
        """
        Filter a list of URLs based on criteria.
        
        Args:
            urls: List of URLs to filter
            target_domain: Only keep URLs from this domain (optional)
            exclude_patterns: Regex patterns to exclude (optional)
            
        Returns:
            Filtered list of URLs
        """
        if exclude_patterns is None:
            exclude_patterns = [
                r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$',
                r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx)$',
                r'\.(zip|tar|gz|rar|7z)$',
                r'^mailto:',
                r'^tel:',
                r'^javascript:',
                r'^#'
            ]
        
        filtered = []
        exclude_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in exclude_patterns]
        
        for url in urls:
            # Skip None or empty URLs
            if not url:
                continue
            
            # Apply exclude patterns
            excluded = False
            for regex in exclude_regexes:
                if regex.search(url):
                    excluded = True
                    break
            
            if excluded:
                continue
            
            # Filter by domain if specified
            if target_domain:
                url_domain = URLHelper.get_domain(url)
                if url_domain != target_domain:
                    continue
            
            filtered.append(url)
        
        return filtered
    
    @staticmethod
    def get_url_depth(url: str) -> int:
        """Calculate the depth of a URL (number of path segments)"""
        try:
            parsed = urlparse(url)
            # Remove leading/trailing slashes and split
            path = parsed.path.strip('/')
            if not path:
                return 0
            return len(path.split('/'))
        except:
            return 0

# Test the URL helper
if __name__ == "__main__":
    helper = URLHelper()
    
    test_urls = [
        "https://example.com/page#section",
        "http://EXAMPLE.COM:80/path/?b=2&a=1",
        "/relative/path",
        "https://example.com/image.png",
        "mailto:test@example.com",
        "javascript:alert('test')"
    ]
    
    print("URL Normalization Test:")
    for url in test_urls:
        normalized = helper.normalize_url(url, "https://example.com")
        print(f"  {url} -> {normalized}")
    
    print(f"\nDomain extraction: {helper.get_domain('https://sub.example.co.uk/path')}")
    print(f"URL depth: {helper.get_url_depth('https://example.com/a/b/c')}")