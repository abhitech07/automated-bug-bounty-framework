from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    IDOR = "insecure_direct_object_reference"
    SSRF = "server_side_request_forgery"
    CSRF = "cross_site_request_forgery"
    OTHER = "other"

# Target Schemas
class TargetBase(BaseModel):
    url: str
    name: Optional[str] = None
    scope_rules: Optional[Dict[str, Any]] = {}

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

# ScanJob Schemas  
class ScanJobBase(BaseModel):
    target_id: int
    scan_config: Optional[Dict[str, Any]] = {}

class ScanJobCreate(ScanJobBase):
    pass

class ScanJobResponse(ScanJobBase):
    id: int
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    
    class Config:
        orm_mode = True