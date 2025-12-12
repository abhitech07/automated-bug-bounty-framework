#!/usr/bin/env python3
"""Test advanced subdomain enumeration"""
import sys
sys.path.insert(0, '.')

from src.modules.recon.advanced_subdomain_enum import AdvancedSubdomainEnumerator

def test_advanced_features():
    """Test advanced enumeration features"""
    print("Testing advanced subdomain enumeration...")
    
    # Create enumerator
    enumerator = AdvancedSubdomainEnumerator(
        domain="google.com",
        max_workers=5,
        timeout=2,
        use_async=False
    )
    
    print("\n1. Testing wordlist loading...")
    print(f"   Wordlist size: {len(enumerator.wordlist)}")
    print(f"   Sample words: {enumerator.wordlist[:10]}")
    
    print("\n2. Testing HTTP validation...")
    # Create a mock result
    from src.modules.recon.subdomain_enum import SubdomainResult
    mock_result = SubdomainResult(
        subdomain="www.google.com",
        ip_addresses=["142.250.185.196"],
        status="active",
        source="test"
    )
    
    # This would make actual HTTP requests
    print("   Note: HTTP validation would make actual requests")
    print("   Skipping in test to avoid network calls")
    
    print("\n3. Testing report generation...")
    enumerator.results = [mock_result]
    report = enumerator.generate_report()
    
    print(f"   Report keys: {list(report.keys())}")
    print(f"   Subdomains in report: {len(report['subdomains'])}")
    
    return True

if __name__ == "__main__":
    success = test_advanced_features()
    sys.exit(0 if success else 1)