from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import enum
import time

Base = declarative_base()

class ScanStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnType(enum.Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    IDOR = "insecure_direct_object_reference"
    SSRF = "server_side_request_forgery"
    CSRF = "cross_site_request_forgery"
    INFO_DISCLOSURE = "information_disclosure"
    DIRECTORY_LISTING = "directory_listing"
    OTHER = "other"

class Target(Base):
    __tablename__ = 'targets'

    id = Column(Integer, primary_key=True, index=True)
    # The root URL or domain to scan
    url = Column(String(2048), nullable=False, index=True)
    # A friendly name for the target
    name = Column(String(255))
    # Scope rules (e.g., include/exclude paths) stored as JSON
    scope_rules = Column(JSON, default=dict)
    # Active or inactive for scanning
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship: One Target can have many ScanJobs
    scan_jobs = relationship("ScanJob", back_populates="target", cascade="all, delete-orphan")

class ScanJob(Base):
    __tablename__ = 'scan_jobs'

    id = Column(Integer, primary_key=True, index=True)
    # Link to the Target
    target_id = Column(Integer, ForeignKey('targets.id', ondelete='CASCADE'))
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    # Config for this specific scan (scan depth, modules to run, etc.)
    scan_config = Column(JSON, default=dict)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = 'findings'

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'))
    vulnerability_type = Column(Enum(VulnType), nullable=False, index=True)
    # Specific URL where the issue was found
    url = Column(Text, nullable=False)
    # The vulnerable parameter (e.g., 'id', 'q')
    parameter = Column(String(500))
    # The payload that triggered the finding
    payload = Column(Text)
    http_method = Column(String(10))
    # The full HTTP request that was sent
    http_request = Column(Text)
    # The full HTTP response received
    http_response = Column(Text)
    # Confidence score from the AI Triage engine (0.0 to 1.0)
    ai_confidence_score = Column(Float, default=0.0)
    # AI classification: 'true_positive', 'false_positive', 'needs_review'
    ai_classification = Column(String(50), default='needs_review')
    # Has this finding been safely verified?
    is_verified = Column(Boolean, default=False)
    # Manual severity override (Critical, High, Medium, Low, Info)
    severity = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan_job = relationship("ScanJob", back_populates="findings")

    # Add these models for storing crawl results
class CrawlResultDB(Base):
    """Database model for storing crawl results"""
    __tablename__ = 'crawl_results'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'))
    url = Column(String(2048), nullable=False, index=True)
    status_code = Column(Integer)
    content_type = Column(String(255))
    content_length = Column(Integer)
    title = Column(String(500))
    links_found = Column(Integer, default=0)
    forms_found = Column(Integer, default=0)
    processing_time = Column(Float)
    is_js_rendered = Column(Boolean, default=False)
    screenshot_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    scan_job = relationship("ScanJob", backref="crawl_results")

class DiscoveredURL(Base):
    """Database model for discovered URLs"""
    __tablename__ = 'discovered_urls'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'))
    url = Column(String(2048), nullable=False, index=True)
    source_url = Column(String(2048))  # Where this URL was discovered
    depth = Column(Integer, default=0)
    discovered_by = Column(String(50))  # 'crawler', 'sitemap', 'common_paths', etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    scan_job = relationship("ScanJob", backref="discovered_urls")

class TechnologyFootprint(Base):
    """Database model for technology detection results"""
    __tablename__ = 'technology_footprints'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'))
    url = Column(String(2048), nullable=False)
    category = Column(String(50))  # 'web_framework', 'cms', 'javascript', etc.
    technology = Column(String(100))
    confidence = Column(Float, default=1.0)
    detected_by = Column(String(50))  # 'header', 'content', 'cookie', 'url_pattern'
    created_at = Column(DateTime, default=datetime.utcnow)
    
class Subdomain(Base):
    """Database model for discovered subdomains"""
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'))
    domain = Column(String(255), nullable=False, index=True)
    subdomain = Column(String(255), nullable=False, index=True)
    ip_addresses = Column(JSON)  # List of IP addresses
    cname = Column(String(255))
    status = Column(String(50))  # active, inactive, active_http
    source = Column(String(50))  # Which method found it
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    response_time = Column(Float)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    scan_job = relationship("ScanJob", backref="subdomains")

class SubdomainEnumerationJob(Base):
    """Database model for subdomain enumeration jobs"""
    __tablename__ = 'subdomain_enumeration_jobs'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id', ondelete='CASCADE'))
    domain = Column(String(255), nullable=False)
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    methods_used = Column(JSON)  # List of methods used
    total_checked = Column(Integer, default=0)
    total_found = Column(Integer, default=0)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    scan_job = relationship("ScanJob", backref="subdomain_enumeration_jobs")
    # Relationship
    scan_job = relationship("ScanJob", backref="technology_footprints")

class SQLInjectionScan(Base):
    """Database model for SQL injection scans"""
    __tablename__ = 'sql_injection_scans'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(255), nullable=False, unique=True, index=True)
    url = Column(String(2048), nullable=False)
    status = Column(String(50), default="pending")
    duration = Column(Float)
    options = Column(JSON, default=dict)
    statistics = Column(JSON, default=dict)
    created_at = Column(Float, default=time.time)

    # Relationship to vulnerabilities
    vulnerabilities = relationship("SQLInjectionVulnerability", back_populates="scan", cascade="all, delete-orphan")

class SQLInjectionVulnerability(Base):
    """Database model for SQL injection vulnerabilities"""
    __tablename__ = 'sql_injection_vulnerabilities'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(255), ForeignKey('sql_injection_scans.scan_id'), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    parameter = Column(String(500))
    payload = Column(Text)
    injection_type = Column(String(50))
    database_type = Column(String(50))
    confidence = Column(Float, default=0.0)
    evidence = Column(JSON, default=dict)
    method = Column(String(10))
    detector = Column(String(50))
    created_at = Column(Float, default=time.time)

    # Relationship to scan
    scan = relationship("SQLInjectionScan", back_populates="vulnerabilities")
