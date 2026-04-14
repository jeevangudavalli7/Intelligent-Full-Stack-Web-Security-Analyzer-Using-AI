"""
Database models for the Security Analyzer application
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON, Float, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(enum.Enum):
    """User roles enumeration"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

class ScanStatus(enum.Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(enum.Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityType(enum.Enum):
    """Vulnerability types"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    INFORMATION_DISCLOSURE = "information_disclosure"
    INSECURE_DESERIALIZATION = "insecure_deserialization"

class User(Base):
    """User model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = relationship("Scan", back_populates="user")

class Target(Base):
    """Target URL model"""
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    name = Column(String(200))
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    last_scan_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    """Scan model"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    scan_type = Column(String(50))  # 'full', 'sqli', 'xss', 'csrf', etc.
    config = Column(JSON)  # Scan configuration
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration = Column(Float)  # in seconds
    progress = Column(Integer, default=0)  # 0-100
    ml_analysis_enabled = Column(Boolean, default=True)
    nlp_report_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    reports = relationship("Report", back_populates="scan")

class Vulnerability(Base):
    """Vulnerability model"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vulnerability_type = Column(Enum(VulnerabilityType))
    severity = Column(Enum(VulnerabilitySeverity))
    title = Column(String(200), nullable=False)
    description = Column(Text)
    url = Column(String(2048))
    method = Column(String(10))  # HTTP method
    param = Column(String(200))  # Parameter name
    payload = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)
    cwe_id = Column(String(20))  # CWE identifier
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    is_false_positive = Column(Boolean, default=False)
    ml_confidence = Column(Float)  # ML model confidence score
    ml_prediction = Column(Boolean)  # ML model prediction
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

class Report(Base):
    """Report model"""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    report_type = Column(String(50))  # 'json', 'html', 'pdf', 'nlp'
    title = Column(String(200))
    content = Column(Text)
    summary = Column(Text)
    ml_insights = Column(JSON)  # ML analysis insights
    nlp_summary = Column(Text)  # Natural language summary
    file_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")

class APIKey(Base):
    """API Key model for programmatic access"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    key_hash = Column(String(255), nullable=False)
    name = Column(String(100))
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

def get_db():
    """Database session dependency"""
    from sqlalchemy.orm import sessionmaker
    from config import DATABASE_URL
    
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Import create_engine at the end to avoid circular imports
from sqlalchemy import create_engine

# This is kept at module level for initial setup
engine = None

def init_db():
    """Initialize database tables"""
    global engine
    from config import DATABASE_URL
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(bind=engine)

