"""
Service for managing subdomain enumeration operations.
"""
import asyncio
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
import logging
from datetime import datetime

from src.core import models
from .advanced_subdomain_enum import AdvancedSubdomainEnumerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SubdomainService:
    """Service for subdomain enumeration"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def start_enumeration(
        self,
        scan_job_id: int,
        domain: str,
        use_advanced: bool = True
    ) -> Dict:
        """
        Start subdomain enumeration for a domain.
        
        Args:
            scan_job_id: ID of the scan job
            domain: Domain to enumerate
            use_advanced: Use advanced enumeration methods
            
        Returns:
            Dictionary with results
        """
        logger.info(f"Starting subdomain enumeration for: {domain}")
        
        try:
            # Create enumeration job record
            enum_job = models.SubdomainEnumerationJob(
                scan_job_id=scan_job_id,
                domain=domain,
                status="running",
                started_at=datetime.utcnow()
            )
            self.db.add(enum_job)
            self.db.commit()
            
            # Initialize enumerator
            if use_advanced:
                enumerator = AdvancedSubdomainEnumerator(
                    domain=domain,
                    max_workers=15,
                    timeout=3,
                    use_async=True
                )
                
                # Run comprehensive enumeration
                results = enumerator.enumerate_comprehensive()
            else:
                from .subdomain_enum import SubdomainEnumerator
                enumerator = SubdomainEnumerator(
                    domain=domain,
                    max_workers=10,
                    timeout=3,
                    use_async=True
                )
                results = enumerator.enumerate_all()
            
            # Save results to database
            saved_count = self.save_results(
                scan_job_id=scan_job_id,
                domain=domain,
                results=results,
                enum_job_id=enum_job.id
            )
            
            # Update enumeration job
            enum_job.status = "completed"
            enum_job.completed_at = datetime.utcnow()
            enum_job.total_checked = enumerator.stats.get('total_checked', 0)
            enum_job.total_found = len(results)
            enum_job.methods_used = enumerator.stats.get('methods_used', [])
            self.db.commit()
            
            # Generate report
            report = self.generate_report(enum_job.id)
            
            logger.info(f"Subdomain enumeration completed: {saved_count} subdomains saved")
            
            return {
                "status": "completed",
                "enumeration_job_id": enum_job.id,
                "domain": domain,
                "subdomains_found": saved_count,
                "methods_used": enum_job.methods_used,
                "report": report
            }
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")
            
            # Update job status
            if 'enum_job' in locals():
                enum_job.status = "failed"
                self.db.commit()
            
            return {
                "status": "failed",
                "error": str(e)
            }
    
    def save_results(
        self,
        scan_job_id: int,
        domain: str,
        results: List,
        enum_job_id: int
    ) -> int:
        """Save subdomain results to database"""
        saved_count = 0
        
        for result in results:
            try:
                subdomain_db = models.Subdomain(
                    scan_job_id=scan_job_id,
                    domain=domain,
                    subdomain=result.subdomain,
                    ip_addresses=result.ip_addresses,
                    cname=result.cname,
                    status=result.status,
                    source=result.source,
                    response_time=getattr(result, 'response_time', 0.0),
                    discovered_at=result.discovered_at
                )
                
                # Add HTTP info if available
                if hasattr(result, 'http_status'):
                    subdomain_db.http_status = result.http_status
                if hasattr(result, 'http_title'):
                    subdomain_db.http_title = result.http_title
                
                self.db.add(subdomain_db)
                saved_count += 1
                
            except Exception as e:
                logger.error(f"Failed to save subdomain {result.subdomain}: {e}")
        
        self.db.commit()
        return saved_count
    
    def generate_report(self, enum_job_id: int) -> Dict:
        """Generate a report for the enumeration job"""
        enum_job = self.db.query(models.SubdomainEnumerationJob).filter(
            models.SubdomainEnumerationJob.id == enum_job_id
        ).first()
        
        if not enum_job:
            return {"error": "Enumeration job not found"}
        
        # Get all subdomains for this job
        subdomains = self.db.query(models.Subdomain).filter(
            models.Subdomain.scan_job_id == enum_job.scan_job_id,
            models.Subdomain.domain == enum_job.domain
        ).all()
        
        # Categorize by source
        by_source = {}
        for subdomain in subdomains:
            source = subdomain.source
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(subdomain.subdomain)
        
        # Categorize by status
        by_status = {}
        for subdomain in subdomains:
            status = subdomain.status
            if status not in by_status:
                by_status[status] = []
            by_status[status].append(subdomain.subdomain)
        
        report = {
            "enumeration_job_id": enum_job.id,
            "domain": enum_job.domain,
            "status": enum_job.status,
            "total_subdomains": len(subdomains),
            "methods_used": enum_job.methods_used or [],
            "statistics": {
                "total_checked": enum_job.total_checked,
                "total_found": enum_job.total_found,
                "by_source": {k: len(v) for k, v in by_source.items()},
                "by_status": {k: len(v) for k, v in by_status.items()}
            },
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "ip_addresses": s.ip_addresses,
                    "status": s.status,
                    "source": s.source,
                    "http_status": s.http_status,
                    "http_title": s.http_title
                }
                for s in subdomains[:100]  # Limit for report
            ]
        }
        
        return report
    
    def get_enumeration_status(self, enum_job_id: int) -> Dict:
        """Get status of an enumeration job"""
        enum_job = self.db.query(models.SubdomainEnumerationJob).filter(
            models.SubdomainEnumerationJob.id == enum_job_id
        ).first()
        
        if not enum_job:
            return {"error": "Enumeration job not found"}
        
        # Count subdomains found so far
        subdomain_count = self.db.query(models.Subdomain).filter(
            models.Subdomain.scan_job_id == enum_job.scan_job_id,
            models.Subdomain.domain == enum_job.domain
        ).count()
        
        return {
            "enumeration_job_id": enum_job.id,
            "domain": enum_job.domain,
            "status": enum_job.status,
            "subdomains_found": subdomain_count,
            "started_at": enum_job.started_at.isoformat() if enum_job.started_at else None,
            "completed_at": enum_job.completed_at.isoformat() if enum_job.completed_at else None
        }

# Test function
def test_subdomain_service():
    """Test the subdomain service"""
    from src.core.database import SessionLocal
    
    db = SessionLocal()
    service = SubdomainService(db)
    
    # Create a test scan job
    test_target = models.Target(
        url="https://example.com",
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
    
    print(f"Testing subdomain service with scan job {test_scan_job.id}...")
    
    # Start enumeration (with a small test)
    result = service.start_enumeration(
        scan_job_id=test_scan_job.id,
        domain="github.com",
        use_advanced=False  # Use basic for test
    )
    
    print(f"Result: {result}")
    
    if result["status"] == "completed":
        # Get status
        status = service.get_enumeration_status(result["enumeration_job_id"])
        print(f"Status: {status}")
    
    # Cleanup
    db.query(models.Subdomain).filter(
        models.Subdomain.scan_job_id == test_scan_job.id
    ).delete()
    db.query(models.SubdomainEnumerationJob).filter(
        models.SubdomainEnumerationJob.scan_job_id == test_scan_job.id
    ).delete()
    db.query(models.ScanJob).filter(
        models.ScanJob.id == test_scan_job.id
    ).delete()
    db.query(models.Target).filter(
        models.Target.id == test_target.id
    ).delete()
    db.commit()
    db.close()
    
    return result

if __name__ == "__main__":
    test_subdomain_service()