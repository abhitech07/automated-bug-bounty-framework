"""
API endpoints for reconnaissance operations.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
import logging

from src.core.database import get_db
from src.core import models
from src.modules.recon.service import ReconnaissanceService
# Add new imports
from src.modules.recon.subdomain_service import SubdomainService

logger = logging.getLogger(__name__)

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

# Add new request models
class SubdomainEnumerationRequest(BaseModel):
    domain: str
    use_advanced: bool = True
    scan_job_id: Optional[int] = None

class SubdomainResultsRequest(BaseModel):
    domain: str
    limit: int = 100
    offset: int = 0

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

# Add new endpoints
@router.post("/enumerate-subdomains", response_model=CrawlStatusResponse)
async def enumerate_subdomains(
    request: SubdomainEnumerationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start subdomain enumeration for a domain.
    
    If scan_job_id is provided, results are linked to that scan job.
    Otherwise, a new scan job is created.
    """
    try:
        # Use provided scan job or create a new one
        if request.scan_job_id:
            scan_job = db.query(models.ScanJob).filter(
                models.ScanJob.id == request.scan_job_id
            ).first()
            if not scan_job:
                raise HTTPException(status_code=404, detail="Scan job not found")
        else:
            # Create a new target for this domain
            target = models.Target(
                url=f"https://{request.domain}",
                name=f"Subdomain Enum - {request.domain}"
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
        
        # Start enumeration in background
        def run_enumeration():
            service = SubdomainService(db)
            service.start_enumeration(
                scan_job_id=scan_job.id,
                domain=request.domain,
                use_advanced=request.use_advanced
            )
        
        background_tasks.add_task(run_enumeration)
        
        # Update scan job status
        scan_job.status = models.ScanStatus.RUNNING
        db.commit()
        
        return CrawlStatusResponse(
            scan_job_id=scan_job.id,
            status="started",
            message=f"Subdomain enumeration started for {request.domain}"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/subdomains/{scan_job_id}")
async def get_subdomains(
    scan_job_id: int,
    domain: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    Get subdomain enumeration results for a scan job.
    
    Args:
        scan_job_id: ID of the scan job
        domain: Filter by specific domain (optional)
        limit: Maximum number of results
        offset: Pagination offset
    """
    # Verify scan job exists
    scan_job = db.query(models.ScanJob).filter(
        models.ScanJob.id == scan_job_id
    ).first()
    
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    # Build query
    query = db.query(models.Subdomain).filter(
        models.Subdomain.scan_job_id == scan_job_id
    )
    
    if domain:
        query = query.filter(models.Subdomain.domain == domain)
    
    # Get total count
    total = query.count()
    
    # Get paginated results
    subdomains = query.order_by(models.Subdomain.discovered_at.desc()).offset(offset).limit(limit).all()
    
    # Get unique domains in results
    domains = db.query(models.Subdomain.domain).filter(
        models.Subdomain.scan_job_id == scan_job_id
    ).distinct().all()
    
    # Get statistics
    status_stats = db.query(
        models.Subdomain.status,
        db.func.count(models.Subdomain.id).label('count')
    ).filter(
        models.Subdomain.scan_job_id == scan_job_id
    ).group_by(models.Subdomain.status).all()
    
    source_stats = db.query(
        models.Subdomain.source,
        db.func.count(models.Subdomain.id).label('count')
    ).filter(
        models.Subdomain.scan_job_id == scan_job_id
    ).group_by(models.Subdomain.source).all()
    
    return {
        "scan_job_id": scan_job_id,
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(subdomains) < total
        },
        "domains": [d[0] for d in domains],
        "statistics": {
            "total_subdomains": total,
            "by_status": {s[0]: s[1] for s in status_stats},
            "by_source": {s[0]: s[1] for s in source_stats}
        },
        "subdomains": [
            {
                "id": s.id,
                "domain": s.domain,
                "subdomain": s.subdomain,
                "ip_addresses": s.ip_addresses,
                "cname": s.cname,
                "status": s.status,
                "source": s.source,
                "http_status": s.http_status,
                "http_title": s.http_title,
                "discovered_at": s.discovered_at.isoformat()
            }
            for s in subdomains
        ]
    }

@router.get("/subdomain-stats/{scan_job_id}")
async def get_subdomain_stats(
    scan_job_id: int,
    db: Session = Depends(get_db)
):
    """
    Get statistics for subdomain enumeration.
    """
    # Get enumeration jobs
    enum_jobs = db.query(models.SubdomainEnumerationJob).filter(
        models.SubdomainEnumerationJob.scan_job_id == scan_job_id
    ).all()
    
    if not enum_jobs:
        raise HTTPException(status_code=404, detail="No enumeration jobs found")
    
    # Get subdomains
    subdomains = db.query(models.Subdomain).filter(
        models.Subdomain.scan_job_id == scan_job_id
    ).all()
    
    # Calculate statistics
    total_subdomains = len(subdomains)
    unique_domains = len(set(s.domain for s in subdomains))
    
    # Active vs inactive
    active_count = len([s for s in subdomains if "active" in s.status])
    
    # Sources
    sources = {}
    for s in subdomains:
        if s.source not in sources:
            sources[s.source] = 0
        sources[s.source] += 1
    
    return {
        "scan_job_id": scan_job_id,
        "enumeration_jobs": len(enum_jobs),
        "total_subdomains": total_subdomains,
        "unique_domains": unique_domains,
        "active_subdomains": active_count,
        "inactive_subdomains": total_subdomains - active_count,
        "sources": sources,
        "recent_jobs": [
            {
                "id": j.id,
                "domain": j.domain,
                "status": j.status,
                "total_found": j.total_found,
                "methods_used": j.methods_used,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None
            }
            for j in enum_jobs[:5]  # Last 5 jobs
        ]
    }

@router.post("/crawl-with-subdomains")
async def crawl_with_subdomains(
    request: StartCrawlRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a comprehensive reconnaissance that includes subdomain enumeration.
    
    This endpoint:
    1. Enumerates subdomains
    2. Crawls discovered subdomains
    3. Returns combined results
    """
    # Create target
    target = models.Target(
        url=str(request.target_url),
        name=f"Comprehensive Recon - {request.target_url.host}"
    )
    db.add(target)
    db.commit()
    
    # Create scan job
    scan_job = models.ScanJob(
        target_id=target.id,
        status=models.ScanStatus.PENDING
    )
    db.add(scan_job)
    db.commit()
    
    def run_comprehensive_recon():
        from src.modules.recon.service import ReconnaissanceService
        from src.modules.recon.subdomain_service import SubdomainService
        
        recon_service = ReconnaissanceService(db)
        subdomain_service = SubdomainService(db)
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(str(request.target_url))
        domain = parsed.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Step 1: Enumerate subdomains
        logger.info(f"Step 1: Enumerating subdomains for {domain}")
        enum_result = subdomain_service.start_enumeration(
            scan_job_id=scan_job.id,
            domain=domain,
            use_advanced=True
        )
        
        # Step 2: Get discovered subdomains
        subdomains = db.query(models.Subdomain).filter(
            models.Subdomain.scan_job_id == scan_job.id,
            models.Subdomain.status.like('active%')
        ).all()
        
        # Step 3: Crawl main target
        logger.info(f"Step 3: Crawling main target: {request.target_url}")
        crawl_result = recon_service.start_crawl(
            scan_job_id=scan_job.id,
            start_url=str(request.target_url),
            crawler_type=request.crawler_type,
            max_pages=request.max_pages,
            max_depth=request.max_depth
        )
        
        # Step 4: Crawl discovered subdomains (limited)
        logger.info(f"Step 4: Crawling discovered subdomains ({len(subdomains)} total)")
        for i, subdomain in enumerate(subdomains[:10]):  # Limit to 10 subdomains
            try:
                url = f"https://{subdomain.subdomain}"
                logger.info(f"  Crawling subdomain {i+1}/{min(10, len(subdomains))}: {url}")
                
                # Create a sub-scan job
                sub_scan = models.ScanJob(
                    target_id=target.id,
                    status=models.ScanStatus.PENDING,
                    scan_config={"parent_scan": scan_job.id}
                )
                db.add(sub_scan)
                db.commit()
                
                # Crawl subdomain
                recon_service.start_crawl(
                    scan_job_id=sub_scan.id,
                    start_url=url,
                    crawler_type="basic",  # Use basic crawler for subdomains
                    max_pages=min(20, request.max_pages),
                    max_depth=min(2, request.max_depth)
                )
                
            except Exception as e:
                logger.error(f"Failed to crawl subdomain {subdomain.subdomain}: {e}")
        
        # Update main scan job
        scan_job.status = models.ScanStatus.COMPLETED
        db.commit()
        
        logger.info("Comprehensive reconnaissance completed")
    
    background_tasks.add_task(run_comprehensive_recon)
    
    return {
        "scan_job_id": scan_job.id,
        "status": "started",
        "message": "Comprehensive reconnaissance started",
        "steps": [
            "1. Subdomain enumeration",
            "2. Main target crawling",
            "3. Discovered subdomain crawling"
        ]
    }