#!/usr/bin/env python3
"""Test script for the crawler"""

import sys
sys.path.insert(0, '.')

from src.modules.recon.crawler import Crawler

def test_basic_crawling():
    """Test basic crawling functionality"""
    print("Testing basic crawler...")
    
    crawler = Crawler(
        max_pages=10,
        delay=2.0,
        stay_on_domain=True,
        max_depth=3,
        exclude_patterns=[
            r'\.(css|js|png|jpg|gif)$',
            r'\.pdf$'
        ]
    )
    
    # Use a test website
    results = crawler.start("http://books.toscrape.com/")
    
    print(f"\nCrawl Summary:")
    print(f"  Total pages crawled: {len(results)}")
    print(f"  Total unique URLs found: {len(crawler.visited_urls)}")
    
    if results:
        print(f"\nSample results:")
        for i, result in enumerate(results[:3]):
            print(f"  {i+1}. {result.url}")
            print(f"     Status: {result.status_code}")
            print(f"     Links found: {len(result.links)}")
            print(f"     Forms found: {len(result.forms)}")
    
    return results

if __name__ == "__main__":
    test_basic_crawling()