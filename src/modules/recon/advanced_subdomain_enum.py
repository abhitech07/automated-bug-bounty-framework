"""
Advanced subdomain enumeration with multiple techniques and wordlists.
"""
import os
import json
import subprocess
import tempfile
from typing import List, Optional
import logging
from datetime import datetime
from .subdomain_enum import SubdomainEnumerator, SubdomainResult

logger = logging.getLogger(__name__)

class AdvancedSubdomainEnumerator(SubdomainEnumerator):
    """Enhanced subdomain enumerator with wordlist support and more techniques"""
    
    def __init__(
        self,
        domain: str,
        max_workers: int = 20,
        timeout: int = 3,
        use_async: bool = True,
        wordlist_path: str = None
    ):
        super().__init__(domain, max_workers, timeout, use_async)
        
        # Load wordlist
        self.wordlist = self.load_wordlist(wordlist_path)
        
        # Statistics
        self.stats = {
            'total_checked': 0,
            'active_found': 0,
            'methods_used': []
        }
    
    def load_wordlist(self, path: Optional[str]) -> List[str]:
        """Load subdomain wordlist from file"""
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    words = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded {len(words)} words from {path}")
                return words
            except Exception as e:
                logger.error(f"Failed to load wordlist {path}: {e}")
        
        # Fallback: large common wordlist
        large_wordlist = self.common_subdomains + [
            # Additional common words
            'alpha', 'beta', 'gamma', 'delta', 'epsilon',
            'auth', 'authentication', 'authorization',
            'backup', 'backups', 'archive', 'archives',
            'client', 'clients', 'customer', 'customers',
            'demo', 'demos', 'example', 'examples',
            'event', 'events', 'meeting', 'meetings',
            'file', 'files', 'upload', 'uploads',
            'game', 'games', 'play', 'player',
            'info', 'information', 'news', 'updates',
            'job', 'jobs', 'career', 'careers',
            'learn', 'learning', 'course', 'courses',
            'live', 'stream', 'streaming', 'video',
            'market', 'marketing', 'sale', 'sales',
            'mobile', 'mobiles', 'phone', 'phones',
            'news', 'newsletter', 'notification',
            'office', 'offices', 'branch', 'branches',
            'payment', 'payments', 'billing', 'invoice',
            'product', 'products', 'service', 'services',
            'research', 'researchers', 'science',
            'secure', 'security', 'safe', 'protection',
            'social', 'network', 'community',
            'system', 'systems', 'platform', 'platforms',
            'team', 'teams', 'group', 'groups',
            'tool', 'tools', 'utility', 'utilities',
            'training', 'trainings', 'workshop',
            'web', 'website', 'site', 'sites',
            'work', 'works', 'project', 'projects',
        ]
        
        # Add permutations
        permutations = []
        for word in large_wordlist[:100]:  # Limit permutations
            permutations.extend([
                f"{word}1", f"{word}2", f"{word}3",
                f"test{word}", f"dev{word}", f"prod{word}",
                f"{word}test", f"{word}dev", f"{word}prod",
            ])
        
        full_list = large_wordlist + permutations
        return list(set(full_list))  # Remove duplicates
    
    def enumerate_comprehensive(self) -> List[SubdomainResult]:
        """
        Run all enumeration techniques in optimal order.
        
        Returns:
            Combined results from all methods
        """
        logger.info(f"Starting comprehensive enumeration for {self.domain}")
        
        all_results = []
        self.stats['methods_used'] = []
        
        # 1. Passive methods (fast, no direct contact)
        logger.info("Phase 1: Passive enumeration...")
        
        # Certificate Transparency
        self.stats['methods_used'].append('certificate_transparency')
        ct_results = self.enumerate_via_certificate_transparency()
        all_results.extend(ct_results)
        logger.info(f"  Certificate Transparency: {len(ct_results)}")
        
        # Web Archives
        self.stats['methods_used'].append('web_archives')
        archive_results = self.enumerate_via_web_archives()
        all_results.extend(archive_results)
        logger.info(f"  Web Archives: {len(archive_results)}")
        
        # 2. DNS-based methods
        logger.info("Phase 2: DNS-based enumeration...")
        
        # DNS Zone Transfer (rare but comprehensive)
        self.stats['methods_used'].append('dns_zone_transfer')
        zone_results = self.enumerate_via_dns_zone_transfer()
        all_results.extend(zone_results)
        logger.info(f"  DNS Zone Transfer: {len(zone_results)}")
        
        # Reverse DNS (if we have IPs)
        if all_results:
            self.stats['methods_used'].append('reverse_dns')
            reverse_results = self.enumerate_via_reverse_dns()
            all_results.extend(reverse_results)
            logger.info(f"  Reverse DNS: {len(reverse_results)}")
        
        # 3. Active enumeration (brute-force)
        logger.info("Phase 3: Active enumeration...")

        # External CLI tools (sublist3r, theHarvester)
        self.stats['methods_used'].append('external_tools')
        cli_results = self.enumerate_via_external_tools()
        all_results.extend(cli_results)
        logger.info(f"  External CLI tools: {len(cli_results)}")

        # DNS brute-force with wordlist
        self.stats['methods_used'].append('dns_bruteforce')

        # Use wordlist in chunks
        chunk_size = 100
        total_chunks = (len(self.wordlist) + chunk_size - 1) // chunk_size

        brute_results = []
        for i in range(0, len(self.wordlist), chunk_size):
            chunk = self.wordlist[i:i + chunk_size]
            chunk_results = self.enumerate_via_dns_bruteforce(chunk)
            brute_results.extend(chunk_results)

            progress = min(i + chunk_size, len(self.wordlist))
            logger.info(f"  Brute-force: {progress}/{len(self.wordlist)} words")

        all_results.extend(brute_results)
        logger.info(f"  DNS Brute-force: {len(brute_results)}")
        
        # 4. Remove duplicates and update stats
        unique_results = []
        seen = set()
        
        for result in all_results:
            if result.subdomain not in seen:
                seen.add(result.subdomain)
                unique_results.append(result)
        
        self.results = unique_results
        self.stats['total_checked'] = len(self.wordlist)
        self.stats['active_found'] = len(unique_results)
        
        # 5. Validate all results with HTTP
        logger.info("Phase 4: HTTP validation...")
        validated_results = self.validate_with_http()
        
        logger.info(f"\nEnumeration completed!")
        logger.info(f"Total subdomains found: {len(validated_results)}")
        logger.info(f"Methods used: {', '.join(self.stats['methods_used'])}")
        
        return validated_results
    
    def validate_with_http(self) -> List[SubdomainResult]:
        """Validate subdomains by making HTTP requests"""
        import requests
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        validated = []
        
        def check_http(subdomain_result: SubdomainResult):
            """Check if subdomain responds to HTTP/HTTPS"""
            protocols = ['https://', 'http://']
            
            for protocol in protocols:
                url = f"{protocol}{subdomain_result.subdomain}"
                try:
                    response = requests.get(
                        url,
                        timeout=3,
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    
                    # Update result with HTTP info
                    subdomain_result.status = "active_http"
                    setattr(subdomain_result, 'http_status', response.status_code)
                    setattr(subdomain_result, 'http_title', self.extract_title(response.text))
                    
                    return subdomain_result
                    
                except requests.RequestException:
                    continue
            
            return subdomain_result
        
        # Use threading for parallel HTTP checks
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for result in self.results:
                future = executor.submit(check_http, result)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    validated_result = future.result(timeout=5)
                    validated.append(validated_result)
                except Exception as e:
                    logger.debug(f"HTTP validation failed: {e}")
        
        return validated
    
    def enumerate_via_external_tools(self) -> List[SubdomainResult]:
        """
        Use external CLI tools like sublist3r and theHarvester for subdomain enumeration.

        Returns:
            List of discovered subdomains from external tools
        """
        results = []

        # Try sublist3r
        try:
            logger.info("Running sublist3r...")
            sublist3r_results = self._run_sublist3r()
            results.extend(sublist3r_results)
            logger.info(f"sublist3r found {len(sublist3r_results)} subdomains")
        except Exception as e:
            logger.warning(f"sublist3r failed: {e}")

        # Try theHarvester
        try:
            logger.info("Running theHarvester...")
            harvester_results = self._run_theharvester()
            results.extend(harvester_results)
            logger.info(f"theHarvester found {len(harvester_results)} subdomains")
        except Exception as e:
            logger.warning(f"theHarvester failed: {e}")

        return results

    def _run_sublist3r(self) -> List[SubdomainResult]:
        """Run sublist3r CLI tool"""
        results = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            output_file = f.name

        try:
            # Run sublist3r command
            cmd = [
                'sublist3r',
                '-d', self.domain,
                '-o', output_file,
                '-t', '10'  # threads
            ]

            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )

            if result.returncode == 0 and os.path.exists(output_file):
                # Read results
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]

                # Validate and create results
                for subdomain in subdomains:
                    if subdomain and subdomain.endswith(self.domain):
                        # Quick DNS check
                        success, ips, cname = self.dns_resolve_sync(subdomain.replace(f'.{self.domain}', ''))

                        if success:
                            result_obj = SubdomainResult(
                                subdomain=subdomain,
                                ip_addresses=ips,
                                cname=cname,
                                status="active",
                                source="sublist3r"
                            )
                            results.append(result_obj)

        except subprocess.TimeoutExpired:
            logger.warning("sublist3r timed out")
        except FileNotFoundError:
            logger.warning("sublist3r not installed or not in PATH")
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)

        return results

    def _run_theharvester(self) -> List[SubdomainResult]:
        """Run theHarvester CLI tool"""
        results = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            output_file = f.name

        try:
            # Run theHarvester command
            cmd = [
                'theHarvester',
                '-d', self.domain,
                '-f', output_file,
                '-l', '100'  # limit
            ]

            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )

            if result.returncode == 0 and os.path.exists(output_file):
                # Read JSON results
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)

                    # Extract subdomains from various sources
                    subdomains = set()

                    # Check different sections
                    for section in ['hosts', 'emails', 'urls']:
                        if section in data:
                            for item in data[section]:
                                if isinstance(item, str) and '.' in item:
                                    # Extract domain from email or URL
                                    if '@' in item:
                                        domain_part = item.split('@')[-1]
                                    elif item.startswith('http'):
                                        from urllib.parse import urlparse
                                        parsed = urlparse(item)
                                        domain_part = parsed.netloc
                                    else:
                                        domain_part = item

                                    if domain_part.endswith(self.domain):
                                        subdomains.add(domain_part)

                    # Validate and create results
                    for subdomain in subdomains:
                        if subdomain != self.domain:
                            # Quick DNS check
                            subdomain_only = subdomain.replace(f'.{self.domain}', '')
                            success, ips, cname = self.dns_resolve_sync(subdomain_only)

                            if success:
                                result_obj = SubdomainResult(
                                    subdomain=subdomain,
                                    ip_addresses=ips,
                                    cname=cname,
                                    status="active",
                                    source="theharvester"
                                )
                                results.append(result_obj)

                except json.JSONDecodeError:
                    logger.warning("Failed to parse theHarvester JSON output")

        except subprocess.TimeoutExpired:
            logger.warning("theHarvester timed out")
        except FileNotFoundError:
            logger.warning("theHarvester not installed or not in PATH")
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)

        return results

    def extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        from bs4 import BeautifulSoup

        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string if soup.title else ""
            return title.strip()[:100]  # Limit length
        except:
            return ""

    def generate_report(self) -> dict:
        """Generate comprehensive enumeration report"""
        report = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'subdomains': []
        }
        
        for result in self.results:
            subdomain_info = {
                'subdomain': result.subdomain,
                'ip_addresses': result.ip_addresses,
                'cname': result.cname,
                'status': result.status,
                'source': result.source,
                'discovered_at': result.discovered_at.isoformat()
            }
            
            # Add HTTP info if available
            if hasattr(result, 'http_status'):
                subdomain_info['http_status'] = result.http_status
            if hasattr(result, 'http_title'):
                subdomain_info['http_title'] = result.http_title
            
            report['subdomains'].append(subdomain_info)
        
        return report

# Test function
def test_advanced_enum():
    """Test advanced subdomain enumeration"""
    import sys
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = "microsoft.com"  # Good test domain with many subdomains
    
    print(f"\nAdvanced subdomain enumeration for: {domain}")
    print("=" * 70)
    
    enumerator = AdvancedSubdomainEnumerator(
        domain=domain,
        max_workers=15,
        timeout=3,
        use_async=True
    )
    
    # Run comprehensive enumeration
    results = enumerator.enumerate_comprehensive()
    
    # Display summary
    print(f"\n{'='*70}")
    print(f"ENUMERATION SUMMARY")
    print(f"{'='*70}")
    print(f"Domain: {domain}")
    print(f"Total subdomains found: {len(results)}")
    print(f"Methods used: {', '.join(enumerator.stats['methods_used'])}")
    print(f"Words checked: {enumerator.stats['total_checked']}")
    
    # Show categorized results
    print(f"\n{'='*70}")
    print(f"CATEGORIZED RESULTS")
    print(f"{'='*70}")
    
    sources = {}
    for result in results:
        source = result.source
        if source not in sources:
            sources[source] = []
        sources[source].append(result)
    
    for source, items in sources.items():
        print(f"\n{source.upper()}: {len(items)} subdomains")
        for i, item in enumerate(items[:3]):  # Show first 3 per source
            print(f"  {i+1}. {item.subdomain}")
            if hasattr(item, 'http_title') and item.http_title:
                print(f"     Title: {item.http_title}")
    
    # Generate report
    report = enumerator.generate_report()
    
    # Save to file
    import json
    filename = f"subdomain_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {filename}")
    
    return results

if __name__ == "__main__":
    from datetime import datetime
    results = test_advanced_enum()