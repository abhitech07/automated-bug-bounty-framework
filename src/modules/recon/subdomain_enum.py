"""
Subdomain enumeration module with multiple techniques.
"""
import dns.resolver
import asyncio
import aiohttp
import aiodns
import requests
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import datetime

from src.utils.url_helpers import URLHelper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SubdomainResult:
    """Data class for subdomain discovery results"""
    subdomain: str
    ip_addresses: List[str]
    cname: Optional[str] = None
    status: str = "unknown"  # active, inactive
    source: str = ""  # Which method found it
    response_time: float = 0.0
    discovered_at: datetime = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now()

class SubdomainEnumerator:
    """Main class for subdomain enumeration"""
    
    def __init__(
        self,
        domain: str,
        max_workers: int = 10,
        timeout: int = 5,
        use_async: bool = True
    ):
        """
        Initialize subdomain enumerator.
        
        Args:
            domain: Target domain (e.g., 'example.com')
            max_workers: Maximum concurrent workers
            timeout: DNS/HTTP timeout in seconds
            use_async: Use async operations for speed
        """
        self.domain = domain.lower().strip()
        self.max_workers = max_workers
        self.timeout = timeout
        self.use_async = use_async
        
        # Results storage
        self.results: List[SubdomainResult] = []
        self.discovered_subdomains: Set[str] = set()
        
        # Common subdomain wordlist
        self.common_subdomains = self.load_common_wordlist()
    
    def load_common_wordlist(self) -> List[str]:
        """Load common subdomain prefixes"""
        return [
            # Very common
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
            'api', 'secure', 'portal', 'docs', 'support', 'shop',
            'store', 'app', 'mobile', 'm', 'static', 'cdn', 'img',
            'images', 'assets', 'media', 'video', 'download',
            
            # Infrastructure
            'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'smtp', 'pop',
            'imap', 'webmail', 'calendar', 'git', 'svn', 'vpn',
            'remote', 'ssh', 'db', 'mysql', 'mssql', 'oracle',
            
            # Environment
            'prod', 'production', 'staging', 'stage', 'test',
            'dev', 'development', 'qa', 'uat', 'preprod',
            
            # Services
            'blog', 'wiki', 'forum', 'community', 'help',
            'status', 'monitor', 'dashboard', 'analytics',
            
            # Geography
            'us', 'uk', 'eu', 'de', 'fr', 'jp', 'cn', 'in',
            'au', 'ca', 'mx', 'br', 'ru', 'sg', 'hk',
            
            # Company specific
            'corp', 'internal', 'intranet', 'partner', 'client',
            'customer', 'employee', 'hr', 'finance', 'legal',
            
            # Common patterns
            'origin', 'edge', 'proxy', 'cache', 'balancer',
            'firewall', 'gateway', 'router', 'switch',
        ]
    
    def dns_resolve_sync(self, subdomain: str) -> Tuple[bool, List[str], Optional[str]]:
        """
        Synchronous DNS resolution.
        
        Returns:
            (success, ip_addresses, cname)
        """
        try:
            full_domain = f"{subdomain}.{self.domain}"
            
            # Resolve A records
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            ip_addresses = []
            
            try:
                answers = resolver.resolve(full_domain, 'A')
                ip_addresses = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Try CNAME
            cname = None
            try:
                cname_answers = resolver.resolve(full_domain, 'CNAME')
                if cname_answers:
                    cname = str(cname_answers[0].target).rstrip('.')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # If we got IPs or CNAME, it's active
            success = len(ip_addresses) > 0 or cname is not None
            
            return success, ip_addresses, cname
            
        except Exception as e:
            logger.debug(f"DNS resolution failed for {subdomain}: {e}")
            return False, [], None
    
    async def dns_resolve_async(self, subdomain: str, session: aiodns.DNSResolver) -> Tuple[bool, List[str], Optional[str]]:
        """
        Asynchronous DNS resolution.
        """
        try:
            full_domain = f"{subdomain}.{self.domain}"
            
            ip_addresses = []
            cname = None
            
            # Try A records
            try:
                a_records = await session.query(full_domain, 'A')
                if a_records:
                    ip_addresses = [record.host for record in a_records]
            except aiodns.error.DNSError:
                pass
            
            # Try CNAME
            try:
                cname_records = await session.query(full_domain, 'CNAME')
                if cname_records:
                    cname = cname_records[0].host.rstrip('.')
            except aiodns.error.DNSError:
                pass
            
            success = len(ip_addresses) > 0 or cname is not None
            return success, ip_addresses, cname
            
        except Exception as e:
            logger.debug(f"Async DNS resolution failed for {subdomain}: {e}")
            return False, [], None
    
    def enumerate_via_dns_bruteforce(self, wordlist: List[str] = None) -> List[SubdomainResult]:
        """
        Brute-force subdomains using DNS resolution.
        
        Args:
            wordlist: Custom wordlist, uses common if None
            
        Returns:
            List of discovered subdomains
        """
        if wordlist is None:
            wordlist = self.common_subdomains
        
        logger.info(f"Starting DNS brute-force for {self.domain} with {len(wordlist)} words")
        
        results = []
        
        if self.use_async:
            # Async version
            results = asyncio.run(self._async_dns_bruteforce(wordlist))
        else:
            # Sync version with threading
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for subdomain in wordlist:
                    future = executor.submit(self._check_subdomain, subdomain)
                    futures.append(future)
                
                for future in futures:
                    try:
                        result = future.result(timeout=self.timeout + 1)
                        if result:
                            results.append(result)
                            self.discovered_subdomains.add(result.subdomain)
                    except Exception as e:
                        logger.debug(f"Thread failed: {e}")
        
        logger.info(f"DNS brute-force completed: {len(results)} subdomains found")
        return results
    
    async def _async_dns_bruteforce(self, wordlist: List[str]) -> List[SubdomainResult]:
        """Async implementation of DNS brute-force"""
        results = []
        
        # Create DNS resolver session
        resolver = aiodns.DNSResolver()
        
        # Process in batches
        batch_size = 50
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            
            tasks = []
            for subdomain in batch:
                task = self.dns_resolve_async(subdomain, resolver)
                tasks.append(task)
            
            # Wait for batch completion
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    continue
                
                success, ips, cname = result
                if success:
                    subdomain = batch[j]
                    result_obj = SubdomainResult(
                        subdomain=f"{subdomain}.{self.domain}",
                        ip_addresses=ips,
                        cname=cname,
                        status="active",
                        source="dns_bruteforce"
                    )
                    results.append(result_obj)
                    self.discovered_subdomains.add(subdomain)
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        return results
    
    def _check_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Check a single subdomain (sync version)"""
        start_time = time.time()
        success, ips, cname = self.dns_resolve_sync(subdomain)
        response_time = time.time() - start_time
        
        if success:
            return SubdomainResult(
                subdomain=f"{subdomain}.{self.domain}",
                ip_addresses=ips,
                cname=cname,
                status="active",
                source="dns_bruteforce",
                response_time=response_time
            )
        return None
    
    def enumerate_via_certificate_transparency(self) -> List[SubdomainResult]:
        """
        Find subdomains via Certificate Transparency logs.
        Uses crt.sh public API.
        """
        results = []
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    if 'name_value' in entry:
                        names = entry['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            
                            # Filter for subdomains of our target
                            if name.endswith(self.domain) and name != self.domain:
                                # Extract subdomain part
                                subdomain = name.replace(f".{self.domain}", "")
                                if '*' not in subdomain:  # Skip wildcards
                                    full_subdomain = f"{subdomain}.{self.domain}"
                                    
                                    if full_subdomain not in self.discovered_subdomains:
                                        # Quick DNS check
                                        success, ips, cname = self.dns_resolve_sync(subdomain)
                                        
                                        if success:
                                            result = SubdomainResult(
                                                subdomain=full_subdomain,
                                                ip_addresses=ips,
                                                cname=cname,
                                                status="active",
                                                source="certificate_transparency"
                                            )
                                            results.append(result)
                                            self.discovered_subdomains.add(full_subdomain)
                
                logger.info(f"Certificate Transparency found {len(results)} subdomains")
            else:
                logger.warning(f"crt.sh API returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"Certificate Transparency enumeration failed: {e}")
        
        return results
    
    def enumerate_via_search_engines(self) -> List[SubdomainResult]:
        """
        Find subdomains via search engines (Google, Bing, etc.)
        Note: This is a basic implementation. Real implementation would need proper API keys.
        """
        results = []
        
        # Search patterns for different engines
        search_patterns = [
            f"site:*.{self.domain}",
            f"inurl:{self.domain}",
        ]
        
        # This is a placeholder - real implementation would use search APIs
        logger.info("Search engine enumeration requires API keys (Google Custom Search, Bing Search, etc.)")
        logger.info("Skipping for now. Consider implementing with proper API keys in production.")
        
        return results
    
    def enumerate_all(self) -> List[SubdomainResult]:
        """
        Run all enumeration methods and combine results.
        
        Returns:
            Combined list of all discovered subdomains
        """
        logger.info(f"Starting comprehensive subdomain enumeration for: {self.domain}")
        
        all_results = []
        
        # Method 1: Certificate Transparency (passive, fast)
        logger.info("1. Checking Certificate Transparency logs...")
        ct_results = self.enumerate_via_certificate_transparency()
        all_results.extend(ct_results)
        
        # Method 2: DNS brute-force (active, slower)
        logger.info("2. Running DNS brute-force...")
        dns_results = self.enumerate_via_dns_bruteforce()
        all_results.extend(dns_results)
        
        # Method 3: Search engines (if implemented)
        logger.info("3. Checking search engines...")
        search_results = self.enumerate_via_search_engines()
        all_results.extend(search_results)
        
        # Remove duplicates
        unique_results = []
        seen = set()
        
        for result in all_results:
            if result.subdomain not in seen:
                seen.add(result.subdomain)
                unique_results.append(result)
        
        self.results = unique_results
        
        logger.info(f"Enumeration completed: {len(unique_results)} unique subdomains found")
        
        return unique_results
    
    def export_results(self, format: str = "json") -> str:
        """
        Export results in specified format.
        
        Args:
            format: 'json', 'csv', or 'txt'
            
        Returns:
            Formatted string
        """
        if format == "json":
            import json
            data = [
                {
                    "subdomain": r.subdomain,
                    "ip_addresses": r.ip_addresses,
                    "cname": r.cname,
                    "status": r.status,
                    "source": r.source,
                    "discovered_at": r.discovered_at.isoformat()
                }
                for r in self.results
            ]
            return json.dumps(data, indent=2)
        
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow(["Subdomain", "IP Addresses", "CNAME", "Status", "Source", "Discovered At"])
            
            # Data
            for r in self.results:
                writer.writerow([
                    r.subdomain,
                    ";".join(r.ip_addresses) if r.ip_addresses else "",
                    r.cname or "",
                    r.status,
                    r.source,
                    r.discovered_at.isoformat()
                ])
            
            return output.getvalue()
        
        elif format == "txt":
            lines = []
            for r in self.results:
                lines.append(f"{r.subdomain}")
                if r.ip_addresses:
                    lines.append(f"  IPs: {', '.join(r.ip_addresses)}")
                if r.cname:
                    lines.append(f"  CNAME: {r.cname}")
                lines.append(f"  Source: {r.source}")
                lines.append("")
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")

# Test function
def test_subdomain_enum():
    """Test the subdomain enumerator"""
    import sys
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = "github.com"  # Good test domain
    
    print(f"\nTesting subdomain enumeration for: {domain}")
    print("=" * 60)
    
    enumerator = SubdomainEnumerator(
        domain=domain,
        max_workers=20,
        timeout=3,
        use_async=True
    )
    
    # Run enumeration
    results = enumerator.enumerate_all()
    
    # Display results
    print(f"\nFound {len(results)} subdomains:")
    print("-" * 60)
    
    for i, result in enumerate(results[:20]):  # Show first 20
        print(f"{i+1}. {result.subdomain}")
        if result.ip_addresses:
            print(f"   IPs: {', '.join(result.ip_addresses)}")
        if result.cname:
            print(f"   CNAME: {result.cname}")
        print(f"   Source: {result.source}")
    
    # Export sample
    if results:
        print(f"\nSample JSON export (first 3):")
        sample_results = results[:3]
        enumerator.results = sample_results  # Temporarily replace
        print(enumerator.export_results("json"))
    
    return results

if __name__ == "__main__":
    results = test_subdomain_enum()

def enumerate_via_dns_zone_transfer(self) -> List[SubdomainResult]:
    """
    Attempt DNS zone transfer (AXFR).
    This rarely works but can reveal everything if misconfigured.
    """
    results = []
    
    # Common nameservers to try
    nameservers = [
        f"ns1.{self.domain}",
        f"ns2.{self.domain}",
        f"dns1.{self.domain}",
        f"dns2.{self.domain}",
    ]
    
    for ns in nameservers:
        try:
            # Try to resolve nameserver first
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']  # Use Google DNS for initial lookup
            
            try:
                ns_ip = str(resolver.resolve(ns, 'A')[0])
            except:
                continue  # Nameserver doesn't exist
            
            # Now try zone transfer
            zone_resolver = dns.resolver.Resolver()
            zone_resolver.nameservers = [ns_ip]
            zone_resolver.timeout = 5
            zone_resolver.lifetime = 5
            
            try:
                answers = zone_resolver.resolve(self.domain, 'AXFR')
                
                for rdata in answers:
                    if hasattr(rdata, 'target'):
                        subdomain = str(rdata.target).rstrip('.')
                        if subdomain.endswith(self.domain) and subdomain != self.domain:
                            # Check if active
                            subdomain_only = subdomain.replace(f".{self.domain}", "")
                            success, ips, cname = self.dns_resolve_sync(subdomain_only)
                            
                            if success:
                                result = SubdomainResult(
                                    subdomain=subdomain,
                                    ip_addresses=ips,
                                    cname=cname,
                                    status="active",
                                    source="dns_zone_transfer"
                                )
                                results.append(result)
                                self.discovered_subdomains.add(subdomain)
                
                if results:
                    logger.info(f"DNS zone transfer successful via {ns}!")
                    break
                    
            except Exception as e:
                logger.debug(f"Zone transfer failed for {ns}: {e}")
                
        except Exception as e:
            logger.debug(f"Failed to test {ns}: {e}")
    
    return results

def enumerate_via_reverse_dns(self, ip_range: str = None) -> List[SubdomainResult]:
    """
    Find subdomains via reverse DNS lookups.
    
    Args:
        ip_range: CIDR range to scan (e.g., '192.168.1.0/24')
                  If None, uses IPs from already discovered subdomains
    """
    results = []
    
    if ip_range:
        # This would require additional implementation for IP range scanning
        logger.info("Reverse DNS scanning of IP ranges requires additional dependencies")
        return results
    
    # Use IPs from already discovered subdomains
    all_ips = set()
    for result in self.results:
        all_ips.update(result.ip_addresses)
    
    if not all_ips:
        return results
    
    logger.info(f"Performing reverse DNS lookups for {len(all_ips)} IPs...")
    
    for ip in list(all_ips)[:50]:  # Limit to first 50 IPs
        try:
            # Reverse DNS lookup
            reversed_dns = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            
            try:
                answers = resolver.resolve(reversed_dns, 'PTR')
                for rdata in answers:
                    hostname = str(rdata.target).rstrip('.')
                    
                    # Check if it's a subdomain of our target
                    if hostname.endswith(self.domain) and hostname != self.domain:
                        if hostname not in self.discovered_subdomains:
                            # Forward lookup to confirm
                            subdomain_only = hostname.replace(f".{self.domain}", "")
                            success, ips, cname = self.dns_resolve_sync(subdomain_only)
                            
                            if success:
                                result = SubdomainResult(
                                    subdomain=hostname,
                                    ip_addresses=ips,
                                    cname=cname,
                                    status="active",
                                    source="reverse_dns"
                                )
                                results.append(result)
                                self.discovered_subdomains.add(hostname)
                                
            except Exception:
                pass  # No PTR record
                
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {ip}: {e}")
    
    return results

def enumerate_via_web_archives(self) -> List[SubdomainResult]:
    """
    Find subdomains via web archives (Wayback Machine).
    """
    results = []
    
    try:
        import re
        
        # Wayback Machine CDX API
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
        
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            # Extract unique subdomains from URLs
            subdomain_pattern = re.compile(r'https?://([^/]+)\.' + re.escape(self.domain))
            found_subdomains = set()
            
            for entry in data[1:]:  # Skip header
                if len(entry) > 0:
                    url = entry[0]
                    match = subdomain_pattern.search(url)
                    if match:
                        subdomain = match.group(1)
                        if subdomain and subdomain != 'www':
                            found_subdomains.add(subdomain)
            
            # Check each discovered subdomain
            for subdomain in found_subdomains:
                full_domain = f"{subdomain}.{self.domain}"
                
                if full_domain not in self.discovered_subdomains:
                    success, ips, cname = self.dns_resolve_sync(subdomain)
                    
                    if success:
                        result = SubdomainResult(
                            subdomain=full_domain,
                            ip_addresses=ips,
                            cname=cname,
                            status="active",
                            source="web_archive"
                        )
                        results.append(result)
                        self.discovered_subdomains.add(full_domain)
            
            logger.info(f"Web archives found {len(results)} subdomains")
            
    except Exception as e:
        logger.error(f"Web archive enumeration failed: {e}")
    
    return results