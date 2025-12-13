"""
API endpoints for SQL injection scanning.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict
from pydantic import BaseModel, HttpUrl, validator

from src.core.database import get_db
from src.core import models
from src.modules.scanners.sqli.service import SQLiScanService

router = APIRouter(prefix="/api/sqli", tags=["sql-injection"])

# Request/Response models
class SQLiScanRequest(BaseModel):
    """Request model for starting a SQLi scan"""
    target_url: HttpUrl
    method: str = "GET"
    parameters: Optional[Dict[str, str]] = None
    data: Optional[Dict[str, str]] = None
    scan_config: Optional[Dict] = None
    
    @validator('method')
    def validate_method(cls, v):
        if v.upper() not in ['GET', 'POST']:
            raise ValueError('Method must be GET or POST')
        return v.upper()

class SQLiScanResponse(BaseModel):
    """Response model for SQLi scan"""
    scan_id: int
    status: str
    message: str
    target_url: str

class SQLiScanStatus(BaseModel):
    """Status model for SQLi scan"""
    scan_id: int
    target_url: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    statistics: Dict[str, any]

class SQLiFindingResponse(BaseModel):
    """Response model for SQLi finding"""
    id: int
    url: str
    parameter: str
    payload: Optional[str]
    technique: str
    confidence: float
    database_type: Optional[str]
    severity: str
    is_verified: bool
    verification_status: str
    false_positive_risk: float
    created_at: str

class VerificationUpdate(BaseModel):
    """Request model for updating verification"""
    is_verified: bool
    verified_by: Optional[str] = None
    notes: Optional[str] = None

@router.post("/scan", response_model=SQLiScanResponse)
async def start_sqli_scan(
    request: SQLiScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a SQL injection scan on a target URL.
    
    This endpoint starts the scan in the background and returns immediately.
    """
    # Create a parent scan job first
    scan_job = models.ScanJob(
        status=models.ScanStatus.PENDING,
        scan_config=request.scan_config or {}
    )
    db.add(scan_job)
    db.commit()
    
    # Create SQLi service
    service = SQLiScanService(db)
    
    # Create SQLi scan job
    sqli_scan = service.create_scan_job(
        target_url=str(request.target_url),
        scan_job_id=scan_job.id,
        scan_config=request.scan_config
    )
    
    # Define background task
    def run_scan():
        try:
            # Create new session for background task
            from src.core.database import SessionLocal
            bg_db = SessionLocal()
            bg_service = SQLiScanService(bg_db)
            
            # Run the scan
            bg_service.scan_url(
                sqli_scan_id=sqli_scan.id,
                url=str(request.target_url),
                method=request.method,
                params=request.parameters,
                data=request.data
            )
            
            bg_db.close()
        except Exception as e:
            print(f"Background scan failed: {e}")
    
    # Add to background tasks
    background_tasks.add_task(run_scan)
    
    return SQLiScanResponse(
        scan_id=sqli_scan.id,
        status="started",
        message="SQL injection scan started in background",
        target_url=str(request.target_url)
    )

@router.get("/status/{scan_id}", response_model=SQLiScanStatus)
async def get_sqli_scan_status(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """
    Get the status of a SQL injection scan.
    """
    service = SQLiScanService(db)
    status = service.get_scan_status(scan_id)
    
    if 'error' in status:
        raise HTTPException(status_code=404, detail=status['error'])
    
    return SQLiScanStatus(**status)

@router.get("/findings/{scan_id}", response_model=List[SQLiFindingResponse])
async def get_sqli_findings(
    scan_id: int,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low|info)$"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    db: Session = Depends(get_db)
):
    """
    Get findings from a SQL injection scan.
    
    Supports filtering by severity and minimum confidence.
    """
    # Verify scan exists
    scan = db.query(models.SQLiScanJob).filter(
        models.SQLiScanJob.id == scan_id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != models.ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400, 
            detail=f"Scan is not completed. Current status: {scan.status.value}"
        )
    
    service = SQLiScanService(db)
    findings = service.get_findings(
        scan_id, limit, offset, severity, min_confidence
    )
    
    return findings

@router.get("/finding/{finding_id}", response_model=SQLiFindingResponse)
async def get_sqli_finding_detail(
    finding_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific SQL injection finding.
    """
    finding = db.query(models.SQLiFinding).filter(
        models.SQLiFinding.id == finding_id
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return SQLiFindingResponse(
        id=finding.id,
        url=finding.url,
        parameter=finding.parameter,
        payload=finding.payload,
        technique=finding.technique,
        confidence=finding.confidence,
        database_type=finding.database_type,
        severity=finding.severity,
        is_verified=finding.is_verified,
        verification_status=finding.verification_status,
        false_positive_risk=finding.false_positive_risk,
        created_at=finding.created_at.isoformat()
    )

@router.put("/finding/{finding_id}/verify")
async def verify_sqli_finding(
    finding_id: int,
    verification: VerificationUpdate,
    db: Session = Depends(get_db)
):
    """
    Update verification status of a SQL injection finding.
    """
    service = SQLiScanService(db)
    success = service.update_finding_verification(
        finding_id=finding_id,
        is_verified=verification.is_verified,
        verified_by=verification.verified_by,
        notes=verification.notes
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return {"message": "Verification status updated successfully"}

@router.get("/statistics")
async def get_sqli_statistics(db: Session = Depends(get_db)):
    """
    Get overall SQL injection scanning statistics.
    """
    service = SQLiScanService(db)
    stats = service.get_scan_statistics()
    
    return stats

@router.get("/recent-scans")
async def get_recent_sqli_scans(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db)
):
    """
    Get recent SQL injection scans.
    """
    scans = db.query(models.SQLiScanJob).order_by(
        models.SQLiScanJob.created_at.desc()
    ).limit(limit).all()
    
    return [
        {
            'id': scan.id,
            'target_url': scan.target_url,
            'status': scan.status.value,
            'vulnerabilities_found': scan.vulnerabilities_found,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        }
        for scan in scans
    ]

@router.get("/test")
async def test_sqli_api():
    """
    Test endpoint to verify SQLi API is working.
    """
    return {
        "message": "SQL Injection API is working",
        "endpoints": [
            "POST /api/sqli/scan - Start a SQLi scan",
            "GET /api/sqli/status/{scan_id} - Get scan status",
            "GET /api/sqli/findings/{scan_id} - Get scan findings",
            "GET /api/sqli/finding/{finding_id} - Get finding details",
            "PUT /api/sqli/finding/{finding_id}/verify - Verify finding",
            "GET /api/sqli/statistics - Get overall statistics",
            "GET /api/sqli/recent-scans - Get recent scans",
        ]
    }