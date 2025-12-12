"""
Service layer for reconnaissance operations.
"""
import asyncio
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
import logging

from src.core import models
from src.core.database import get_db
from .crawler_manager import CrawlerManager, CrawlerType
from .discovery import AdvancedDiscovery
from src.utils.url_helpers import URLHelper

logger = logging.getLogger(__name__)

class ReconnaissanceService:
    """Service for managing reconnaissance operations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.discovery = AdvancedDiscovery()
    
    def start_crawl(
        self,
        scan_job_id: int,
        start_url: str,
        crawler_type: str = "hybrid",
        max_pages: int = 100,
        max_depth: int = 5
    ) -> Dict:
        """
        Start a reconnaissance crawl.
        
        Args:
            scan_job_id: ID of the scan job
            start_url: URL to start crawling from
            crawler_type: Type of crawler to use
            max_pages: Maximum pages to crawl
            max_depth: Maximum crawl depth
            
        Returns:
            Dictionary with crawl results
        """
        # Get scan job
        scan_job = self.db.query(models.ScanJob).filter(
            models.ScanJob.id == scan_job_id
        ).first()
        
        if not scan_job:
            raise ValueError(f"Scan job {scan_job_id} not found")
        
        logger.info(f"Starting reconnaissance for scan job {scan_job_id}")
        
        # Update scan job status
        scan_job.status = models.ScanStatus.RUNNING
        self.db.commit()
        
        try:
            # Initialize crawler
            crawler_type_enum = CrawlerType(crawler_type.lower())
            crawler_manager = CrawlerManager(
                crawler_type=crawler_type_enum,
                max_pages=max_pages
            )
            
            # Perform advanced discovery first
            logger.info("Performing advanced discovery...")
            
            # Check robots.txt
            robots_info = self.discovery.check_robots_txt(start_url)
            
            # Parse sitemaps if available
            sitemap_urls = []
            if robots_info.sitemaps:
                logger.info(f"Found {len(robots_info.sitemaps)} sitemaps")
                sitemap_urls = robots_info.sitemaps
            
            # Discover common paths
            common_paths = self.discovery.discover_from_common_paths(start_url)
            logger.info(f"Discovered {len(common_paths)} common paths")
            
            # Start crawling
            logger.info("Starting main crawl...")
            crawl_results = crawler_manager.start(start_url)
            
            # Save results to database
            self.save_crawl_results(
                scan_job_id=scan_job_id,
                start_url=start_url,
                crawl_results=crawl_results,
                robots_info=robots_info,
                sitemap_urls=sitemap_urls,
                common_paths=common_paths
            )
            
            # Update scan job
            scan_job.status = models.ScanStatus.COMPLETED
            self.db.commit()
            
            return {
                "status": "completed",
                "pages_crawled": len(crawl_results),
                "urls_discovered": len(crawl_results) * 10,  # Estimate
                "message": "Reconnaissance completed successfully"
            }
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            
            # Update scan job status
            scan_job.status = models.ScanStatus.FAILED
            self.db.commit()
            
            return {
                "status": "failed",
                "error": str(e),
                "message": "Reconnaissance failed"
            }
    
    def save_crawl_results(
        self,
        scan_job_id: int,
        start_url: str,
        crawl_results: List,
        robots_info,
        sitemap_urls: List[str],
        common_paths: List[str]
    ):
        """Save crawl results to database"""
        # Save main crawl results
        for result in crawl_results:
            crawl_result_db = models.CrawlResultDB(
                scan_job_id=scan_job_id,
                url=result.url,
                status_code=getattr(result, 'status_code', 200),
                content_type=getattr(result, 'content_type', ''),
                content_length=getattr(result, 'content_length', 0),
                title=getattr(result, 'title', '')[:500],
                links_found=len(getattr(result, 'links', [])),
                forms_found=len(getattr(result, 'forms', [])),
                processing_time=getattr(result, 'processing_time', 0),
                is_js_rendered=hasattr(result, 'html')  # Playwright results have html
            )
            self.db.add(crawl_result_db)
        
        # Save discovered URLs from sitemaps
        for sitemap_url in sitemap_urls[:10]:  # Limit to first 10 sitemaps
            sitemap_entry = models.DiscoveredURL(
                scan_job_id=scan_job_id,
                url=sitemap_url,
                source_url=start_url,
                discovered_by='sitemap'
            )
            self.db.add(sitemap_entry)
        
        # Save discovered common paths
        for path in common_paths:
            discovered_url = models.DiscoveredURL(
                scan_job_id=scan_job_id,
                url=path,
                source_url=start_url,
                discovered_by='common_paths'
            )
            self.db.add(discovered_url)
        
        # Commit all changes
        self.db.commit()
        
        logger.info(f"Saved {len(crawl_results)} crawl results to database")

# Test the service
def test_recon_service():
    """Test the reconnaissance service"""
    from src.core.database import SessionLocal
    
    db = SessionLocal()
    service = ReconnaissanceService(db)
    
    # Create a test scan job
    test_target = models.Target(
        url="http://books.toscrape.com/",
        name="Test Target"
    )
    db.add(test_target)
    db.commit()
    
    test_scan_job = models.ScanJob(
        target_id=test_target.id,
        status=models.ScanStatus.PENDING
    )
    db.add(test_scan_job)
    db.commit()
    
    # Start reconnaissance
    print(f"Starting reconnaissance for scan job {test_scan_job.id}...")
    result = service.start_crawl(
        scan_job_id=test_scan_job.id,
        start_url="http://books.toscrape.com/",
        crawler_type="basic",
        max_pages=5
    )
    
    print(f"Result: {result}")
    
    # Check results in database
    crawl_results = db.query(models.CrawlResultDB).filter(
        models.CrawlResultDB.scan_job_id == test_scan_job.id
    ).all()
    
    print(f"\nCrawl results in database: {len(crawl_results)}")
    for i, res in enumerate(crawl_results[:3]):
        print(f"  {i+1}. {res.url} - Status: {res.status_code}")
    
    db.close()
    return result

if __name__ == "__main__":
    test_recon_service()