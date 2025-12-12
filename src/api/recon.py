"""
API endpoints for reconnaissance operations.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel, HttpUrl

from src.core.database import get_db
from src.core import models
from src.modules.recon.service import ReconnaissanceService

router = APIRouter(prefix="/api/recon", tags=["reconnaissance"])

# Request/Response models
class StartCrawlRequest(BaseModel):
    target_url: HttpUrl
    crawler_type: str = "hybrid"
    max_pages: int = 100
    max_depth: int = 5

class CrawlStatusResponse(BaseModel):
    scan_job_id: int
    status: str
    pages_crawled: int = 0
    urls_discovered: int = 0
    message: str

@router.post("/start-crawl", response_model=CrawlStatusResponse)
async def start_crawl(
    request: StartCrawlRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a reconnaissance crawl.
    
    This endpoint starts a crawl in the background and returns immediately.
    """
    # Create a new target
    target = models.Target(
        url=str(request.target_url),
        name=f"Crawl - {request.target_url.host}"
    )
    db.add(target)
    db.commit()
    
    # Create a scan job
    scan_job = models.ScanJob(
        target_id=target.id,
        status=models.ScanStatus.PENDING
    )
    db.add(scan_job)
    db.commit()
    
    # Start crawl in background
    def run_crawl():
        service = ReconnaissanceService(db)
        service.start_crawl(
            scan_job_id=scan_job.id,
            start_url=str(request.target_url),
            crawler_type=request.crawler_type,
            max_pages=request.max_pages,
            max_depth=request.max_depth
        )
    
    background_tasks.add_task(run_crawl)
    
    return CrawlStatusResponse(
        scan_job_id=scan_job.id,
        status="started",
        message="Crawl started in background"
    )

@router.get("/status/{scan_job_id}", response_model=CrawlStatusResponse)
async def get_crawl_status(
    scan_job_id: int,
    db: Session = Depends(get_db)
):
    """
    Get the status of a reconnaissance crawl.
    """
    scan_job = db.query(models.ScanJob).filter(
        models.ScanJob.id == scan_job_id
    ).first()
    
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    # Get crawl results count
    pages_crawled = db.query(models.CrawlResultDB).filter(
        models.CrawlResultDB.scan_job_id == scan_job_id
    ).count()
    
    urls_discovered = db.query(models.DiscoveredURL).filter(
        models.DiscoveredURL.scan_job_id == scan_job_id
    ).count()
    
    return CrawlStatusResponse(
        scan_job_id=scan_job.id,
        status=scan_job.status.value,
        pages_crawled=pages_crawled,
        urls_discovered=urls_discovered,
        message=f"Crawl is {scan_job.status.value}"
    )

@router.get("/results/{scan_job_id}")
async def get_crawl_results(
    scan_job_id: int,
    db: Session = Depends(get_db)
):
    """
    Get the results of a completed reconnaissance crawl.
    """
    # Verify scan job exists and is completed
    scan_job = db.query(models.ScanJob).filter(
        models.ScanJob.id == scan_job_id
    ).first()
    
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    if scan_job.status != models.ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400, 
            detail=f"Scan job is not completed. Current status: {scan_job.status.value}"
        )
    
    # Get crawl results
    crawl_results = db.query(models.CrawlResultDB).filter(
        models.CrawlResultDB.scan_job_id == scan_job_id
    ).all()
    
    # Get discovered URLs
    discovered_urls = db.query(models.DiscoveredURL).filter(
        models.DiscoveredURL.scan_job_id == scan_job_id
    ).all()
    
    # Get technology footprints
    technologies = db.query(models.TechnologyFootprint).filter(
        models.TechnologyFootprint.scan_job_id == scan_job_id
    ).all()
    
    return {
        "scan_job": {
            "id": scan_job.id,
            "status": scan_job.status.value,
            "created_at": scan_job.created_at
        },
        "summary": {
            "pages_crawled": len(crawl_results),
            "urls_discovered": len(discovered_urls),
            "technologies_detected": len(technologies)
        },
        "crawl_results": [
            {
                "url": result.url,
                "status_code": result.status_code,
                "content_type": result.content_type,
                "links_found": result.links_found,
                "forms_found": result.forms_found
            }
            for result in crawl_results[:50]  # Limit to first 50
        ],
        "discovered_urls": [
            {
                "url": url.url,
                "discovered_by": url.discovered_by,
                "source_url": url.source_url
            }
            for url in discovered_urls[:50]  # Limit to first 50
        ],
        "technologies": [
            {
                "category": tech.category,
                "technology": tech.technology,
                "confidence": tech.confidence
            }
            for tech in technologies
        ]
    }