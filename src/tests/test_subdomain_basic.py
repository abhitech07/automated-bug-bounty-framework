#!/usr/bin/env python3
"""Basic test for subdomain enumeration"""
import sys
sys.path.insert(0, '.')

from src.modules.recon.subdomain_enum import SubdomainEnumerator

def test_basic_enumeration():
    """Test basic subdomain enumeration"""
    print("Testing subdomain enumeration...")
    
    # Test with a domain that should have some subdomains
    enumerator = SubdomainEnumerator(
        domain="github.com",
        max_workers=5,
        timeout=2,
        use_async=False  # Use sync for simple test
    )
    
    # Test DNS resolution
    print("\n1. Testing DNS resolution...")
    success, ips, cname = enumerator.dns_resolve_sync("www")
    print(f"   www.github.com -> Success: {success}, IPs: {ips}")
    
    # Test with non-existent
    success, ips, cname = enumerator.dns_resolve_sync("nonexistent12345")
    print(f"   nonexistent12345.github.com -> Success: {success}")
    
    # Test brute-force with small wordlist
    print("\n2. Testing brute-force with common subdomains...")
    common = ['www', 'api', 'docs', 'help']
    results = enumerator.enumerate_via_dns_bruteforce(common)
    
    print(f"   Found {len(results)} active subdomains:")
    for result in results:
        print(f"   - {result.subdomain}: {result.ip_addresses}")
    
    return len(results) > 0

if __name__ == "__main__":
    success = test_basic_enumeration()
    sys.exit(0 if success else 1)