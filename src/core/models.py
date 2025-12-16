"""
Complete database models for the Bug Bounty Framework.
"""
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, JSON, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()

# ============================================================================
# ENUMS
# ============================================================================

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnType(str, enum.Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    IDOR = "insecure_direct_object_reference"
    SSRF = "server_side_request_forgery"
    CSRF = "cross_site_request_forgery"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_BYPASS = "authentication_bypass"
    OTHER = "other"

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# ============================================================================
# TARGET & SCAN MANAGEMENT
# ============================================================================

class Target(Base):
    """Represents a target URL/domain"""
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True)
    url = Column(String(2048), unique=True, nullable=False, index=True)
    name = Column(String(255))
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    scope_rules = Column(JSON, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan_jobs = relationship("ScanJob", back_populates="target")

class ScanJob(Base):
    """Represents a complete scan job"""
    __tablename__ = "scan_jobs"
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)
    scan_config = Column(JSON, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    target = relationship("Target", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="scan_job")
    crawl_results = relationship("CrawlResultDB", back_populates="scan_job")
    discovered_urls = relationship("DiscoveredURL", back_populates="scan_job")
    subdomains = relationship("Subdomain", back_populates="scan_job")

# ============================================================================
# RECONNAISSANCE
# ============================================================================

class CrawlResultDB(Base):
    """Results from crawling a page"""
    __tablename__ = "crawl_results"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    status_code = Column(Integer)
    content_type = Column(String(255))
    content_length = Column(Integer)
    title = Column(String(500))
    links_found = Column(Integer, default=0)
    forms_found = Column(Integer, default=0)
    processing_time = Column(Float)
    is_js_rendered = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="crawl_results")

class DiscoveredURL(Base):
    """Discovered URLs during reconnaissance"""
    __tablename__ = "discovered_urls"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    source_url = Column(String(2048))
    discovered_by = Column(String(100))  # e.g., 'crawl', 'sitemap', 'common_paths'
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="discovered_urls")

class TechnologyFootprint(Base):
    """Detected technologies"""
    __tablename__ = "technology_footprints"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    category = Column(String(100))
    technology = Column(String(255))
    confidence = Column(Float)
    
    created_at = Column(DateTime, default=datetime.utcnow)

class Subdomain(Base):
    """Discovered subdomains"""
    __tablename__ = "subdomains"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    subdomain = Column(String(255), nullable=False)
    ip_addresses = Column(JSON, default=[])
    cname = Column(String(255))
    status = Column(String(50))
    source = Column(String(100))
    response_time = Column(Float)
    http_status = Column(Integer)
    http_title = Column(String(500))
    
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="subdomains")

class SubdomainEnumerationJob(Base):
    """Subdomain enumeration job tracking"""
    __tablename__ = "subdomain_enumeration_jobs"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    status = Column(String(50), default="pending")
    total_checked = Column(Integer, default=0)
    total_found = Column(Integer, default=0)
    methods_used = Column(JSON, default=[])
    
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

# ============================================================================
# VULNERABILITY FINDINGS
# ============================================================================

class Finding(Base):
    """Discovered vulnerabilities"""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    
    url = Column(String(2048), nullable=False)
    parameter = Column(String(500))
    vuln_type = Column(SQLEnum(VulnType), nullable=False, index=True)
    severity = Column(SQLEnum(Severity), index=True)
    
    payload = Column(Text)
    evidence = Column(JSON, default={})
    description = Column(Text)
    
    confidence = Column(Float, default=0.0)
    false_positive_risk = Column(Float, default=0.0)
    
    is_verified = Column(Boolean, default=False)
    verification_status = Column(String(50), default="unverified")
    verified_by = Column(String(255))
    verification_notes = Column(Text)
    
    remediation = Column(Text)
    references = Column(JSON, default=[])
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="findings")

# ============================================================================
# SQL INJECTION SPECIFIC
# ============================================================================

class SQLiScanJob(Base):
    """SQL injection specific scan job"""
    __tablename__ = "sqli_scan_jobs"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(String(50), default="pending")
    vulnerabilities_found = Column(Integer, default=0)
    
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    duration = Column(Float)

class SQLiFinding(Base):
    """SQL injection findings"""
    __tablename__ = "sqli_findings"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), nullable=False, index=True)
    
    url = Column(String(2048), nullable=False)
    parameter = Column(String(500))
    technique = Column(String(100))  # boolean, error, time, union, blind
    database_type = Column(String(50))
    
    payload = Column(Text)
    confidence = Column(Float, default=0.0)
    evidence = Column(JSON, default={})
    method = Column(String(10), default="GET")
    detector = Column(String(50))
    
    is_verified = Column(Boolean, default=False)
    verification_status = Column(String(50), default="unverified")
    false_positive_risk = Column(Float, default=0.0)
    
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# AI TRIAGE & ML
# ============================================================================

class AITrainingData(Base):
    """Training data for AI models"""
    __tablename__ = "ai_training_data"
    
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    
    feature_vector = Column(JSON)
    ground_truth_label = Column(String(50))  # vulnerable, false_positive, etc
    model_version = Column(String(50))
    prediction_confidence = Column(Float)
    
    created_at = Column(DateTime, default=datetime.utcnow)

class ModelPerformance(Base):
    """Track ML model performance"""
    __tablename__ = "model_performance"
    
    id = Column(Integer, primary_key=True)
    model_version = Column(String(50), unique=True)
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    false_positive_rate = Column(Float)
    
    tested_on = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=False)

# ============================================================================
# REPORTING & STATISTICS
# ============================================================================

class ScanReport(Base):
    """Generated scan reports"""
    __tablename__ = "scan_reports"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    
    title = Column(String(255))
    executive_summary = Column(Text)
    detailed_findings = Column(JSON)
    recommendations = Column(Text)
    
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    generated_at = Column(DateTime, default=datetime.utcnow)

class ScanStatistics(Base):
    """Scan statistics for analytics"""
    __tablename__ = "scan_statistics"
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    
    total_urls_tested = Column(Integer, default=0)
    total_parameters_tested = Column(Integer, default=0)
    total_payloads_sent = Column(Integer, default=0)
    
    requests_made = Column(Integer, default=0)
    errors_encountered = Column(Integer, default=0)
    
    execution_time = Column(Float)
    false_positive_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)