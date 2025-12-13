"""
SQL Injection API endpoints.
Provides RESTful interface for SQL injection scanning operations.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import uuid
import logging

from ..modules.scanners.sql_injection.service import sql_injection_service

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/api/sql-injection",
    tags=["sql-injection"],
    responses={404: {"description": "Not found"}},
)

# Pydantic models
class ScanOptions(BaseModel):
    """Options for SQL injection scan"""
    timeout: int = Field(default=10, description="Request timeout in seconds")
    max_requests: int = Field(default=100, description="Maximum requests per parameter")
    delay: float = Field(default=0.5, description="Delay between requests in seconds")
    test_boolean: bool = Field(default=True, description="Test boolean-based injection")
    test_error: bool = Field(default=True, description="Test error-based injection")
    test_time: bool = Field(default=False, description="Test time-based injection")
    test_union: bool = Field(default=True, description="Test union-based injection")
    db_types: List[str] = Field(default=["generic", "mysql", "postgresql"],
                               description="Database types to test")

class ScanRequest(BaseModel):
    """Request model for SQL injection scan"""
    url: str = Field(..., description="Target URL to scan")
    options: Optional[ScanOptions] = Field(default=None, description="Scan options")

class ScanResponse(BaseModel):
    """Response model for scan initiation"""
    scan_id: str
    url: str
    status: str
    message: str

class VulnerabilitySummary(BaseModel):
    """Summary of a vulnerability finding"""
    id: Optional[int] = None
    url: str
    parameter: str
    payload: str
    injection_type: str
    database_type: str
    confidence: float
    evidence: Dict[str, Any]
    method: str
    detector: str
    created_at: Optional[float] = None

class ScanSummary(BaseModel):
    """Summary of a scan"""
    scan_id: str
    url: str
    status: str
    duration: Optional[float] = None
    vulnerabilities_found: int = 0
    created_at: float

class ScanResults(BaseModel):
    """Complete scan results"""
    scan_id: str
    url: str
    status: str
    duration: float
    options: Dict[str, Any]
    statistics: Dict[str, Any]
    vulnerabilities: List[VulnerabilitySummary]
    created_at: float

# Background task function
async def perform_scan_background(scan_id: str, url: str, options: Dict[str, Any]):
    """Background task to perform SQL injection scan"""
    try:
        logger.info(f"Starting background scan {scan_id} for URL: {url}")

        # Perform the scan
        results = await sql_injection_service.scan_url(
            url=url,
            scan_id=scan_id,
            options=options
        )

        logger.info(f"Completed background scan {scan_id}: {len(results.get('vulnerabilities', []))} vulnerabilities found")

    except Exception as e:
        logger.error(f"Background scan {scan_id} failed: {e}")

# API endpoints
@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a SQL injection scan.

    This endpoint initiates an asynchronous SQL injection scan on the provided URL.
    The scan runs in the background and results can be retrieved using the scan_id.
    """
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())

        # Convert options to dict
        options = request.options.dict() if request.options else {}

        # Add scan to background tasks
        background_tasks.add_task(
            perform_scan_background,
            scan_id=scan_id,
            url=request.url,
            options=options
        )

        logger.info(f"Initiated SQL injection scan {scan_id} for URL: {request.url}")

        return ScanResponse(
            scan_id=scan_id,
            url=request.url,
            status="started",
            message="SQL injection scan initiated successfully"
        )

    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@router.get("/scan/{scan_id}", response_model=ScanResults)
async def get_scan_results(scan_id: str):
    """
    Get results of a SQL injection scan.

    Returns the complete results of a scan identified by scan_id.
    If the scan is still running, returns partial results.
    """
    try:
        results = await sql_injection_service.get_scan_results(scan_id)

        if not results:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResults(**results)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan results: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scan results: {str(e)}")

@router.get("/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = 50, offset: int = 0):
    """
    List recent SQL injection scans.

    Returns a list of recent scans with summary information.
    """
    try:
        scans = await sql_injection_service.list_scans(limit=limit, offset=offset)
        return [ScanSummary(**scan) for scan in scans]

    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list scans: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint for SQL injection module"""
    return {"status": "healthy", "module": "sql_injection"}
