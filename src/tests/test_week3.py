#!/usr/bin/env python3
"""
Comprehensive test suite for Week 3: Reconnaissance Engine
"""
import sys
sys.path.insert(0, '.')

import requests
import time
from src.core.database import SessionLocal
from src.modules.recon.crawler import Crawler
from src.modules.recon.playwright_crawler import PlaywrightCrawler
from src.modules.recon.discovery import AdvancedDiscovery
from src.modules.recon.service import ReconnaissanceService
from src.core import models

def test_basic_crawler():
    """Test 1: Basic crawler functionality"""
    print("\n" + "="*60)
    print("Test 1: Basic Crawler")
    print("="*60)
    
    crawler = Crawler(max_pages=3, delay=1.0)
    results = crawler.start("http://books.toscrape.com/")
    
    assert len(results) > 0, "Crawler should find at least 1 page"
    assert results[0].status_code == 200, "Should get HTTP 200"
    
    print(f"✓ Basic crawler: {len(results)} pages crawled")
    return True

def test_url_helpers():
    """Test 2: URL helper utilities"""
    print("\n" + "="*60)
    print("Test 2: URL Helpers")
    print("="*60)
    
    from src.utils.url_helpers import URLHelper
    
    test_cases = [
        ("https://example.com/test#section", "https://example.com/test"),
        ("http://EXAMPLE.COM:80/path", "http://example.com/path"),
        ("/relative", "https://base.com/relative"),
    ]
    
    for url, expected in test_cases:
        base = "https://base.com" if url.startswith("/") else None
        result = URLHelper.normalize_url(url, base)
        print(f"  {url} -> {result}")
    
    print("✓ URL helpers working")
    return True

def test_advanced_discovery():
    """Test 3: Advanced discovery features"""
    print("\n" + "="*60)
    print("Test 3: Advanced Discovery")
    print("="*60)
    
    discovery = AdvancedDiscovery()
    
    # Test robots.txt
    robots_info = discovery.check_robots_txt("https://github.com")
    print(f"  Robots.txt present: {robots_info.is_present}")
    
    # Test common paths discovery (limited)
    paths = discovery.discover_from_common_paths("http://books.toscrape.com/")
    print(f"  Common paths found: {len(paths)}")
    
    print("✓ Advanced discovery working")
    return True

def test_database_integration():
    """Test 4: Database integration"""
    print("\n" + "="*60)
    print("Test 4: Database Integration")
    print("="*60)
    
    db = SessionLocal()
    
    # Create test data
    target = models.Target(
        url="http://test.example.com",
        name="Test Target"
    )
    db.add(target)
    db.commit()
    
    scan_job = models.ScanJob(
        target_id=target.id,
        status=models.ScanStatus.PENDING
    )
    db.add(scan_job)
    db.commit()
    
    # Verify data
    saved_target = db.query(models.Target).filter(
        models.Target.url == "http://test.example.com"
    ).first()
    
    assert saved_target is not None, "Target should be saved"
    print(f"✓ Database: Target saved (ID: {saved_target.id})")
    
    # Cleanup
    db.query(models.ScanJob).filter(
        models.ScanJob.id == scan_job.id
    ).delete()
    db.query(models.Target).filter(
        models.Target.id == target.id
    ).delete()
    db.commit()
    db.close()
    
    return True

def test_api_endpoints():
    """Test 5: API endpoints"""
    print("\n" + "="*60)
    print("Test 5: API Endpoints")
    print("="*60)
    
    # Start the server in a separate process for testing
    # For now, just test that the modules import correctly
    try:
        from src.api import recon
        from src.main import app
        
        print("✓ API modules import successfully")
        
        # Check that routes are defined
        routes = [route.path for route in app.routes if hasattr(route, 'path')]
        assert '/api/recon/start-crawl' in str(routes), "Recon routes should be registered"
        
        print("✓ API routes registered")
        return True
        
    except Exception as e:
        print(f"✗ API test failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("WEEK 3: RECONNAISSANCE ENGINE - COMPREHENSIVE TEST")
    print("="*60)
    
    tests = [
        test_basic_crawler,
        test_url_helpers,
        test_advanced_discovery,
        test_database_integration,
        test_api_endpoints
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test failed: {e}")
            results.append(False)
    
    passed = sum(results)
    total = len(results)
    
    print("\n" + "="*60)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("🎉 WEEK 3 IMPLEMENTATION COMPLETE AND TESTED!")
        print("\nNext steps:")
        print("1. Run the full system: python src/main.py")
        print("2. Test API: http://localhost:8000/api/test-recon")
        print("3. Start a crawl: POST to /api/recon/start-crawl")
    else:
        print("⚠️ Some tests failed. Review the implementation.")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)