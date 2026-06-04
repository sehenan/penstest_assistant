"""
Pydantic Models for Request/Response Validation
Advanced validation models for SIATI API
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, EmailStr
from enum import Enum


# ============================================================================
# ENUMS
# ============================================================================

class SeverityLevel(str, Enum):
    """Severity levels for vulnerabilities"""
    INFO = "info"
    LOW = "faible"
    MEDIUM = "moyenne"
    HIGH = "haute"
    CRITICAL = "critique"


class VulnerabilitySource(str, Enum):
    """Sources of vulnerability data"""
    NMAP = "nmap"
    NESSUS = "nessus"
    OPENVAS = "openvas"
    MANUAL = "manual"


class ReportStage(str, Enum):
    """Stages of report generation"""
    AUDIT = "audit"
    PAYLOAD = "payload"
    FINAL = "final"


class UserRole(str, Enum):
    """User roles for authentication"""
    ADMIN = "admin"
    USER = "user"
    ANALYST = "analyst"


# ============================================================================
# REQUEST MODELS
# ============================================================================

class UserLoginRequest(BaseModel):
    """User login request model"""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=8, max_length=100, description="Password")

    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

    @validator('password')
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserCreateRequest(BaseModel):
    """User creation request model"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    role: UserRole = Field(default=UserRole.USER)
    full_name: Optional[str] = Field(None, max_length=100)


class VulnerabilityFilterRequest(BaseModel):
    """Vulnerability filter request model"""
    severity: Optional[SeverityLevel] = None
    source: Optional[VulnerabilitySource] = None
    search_query: Optional[str] = Field(None, max_length=200, alias="q")
    cvss_min: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_max: Optional[float] = Field(None, ge=0.0, le=10.0)
    has_exploit: Optional[bool] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ScanUploadRequest(BaseModel):
    """Scan file upload request model"""
    scan_type: VulnerabilitySource = Field(..., description="Type of scan file")
    description: Optional[str] = Field(None, max_length=500, description="Scan description")
    tags: Optional[List[str]] = Field(None, max_items=10, description="Tags for organization")


class PlaybookGenerationRequest(BaseModel):
    """Playbook generation request model"""
    vuln_id: int = Field(..., gt=0, description="Vulnerability ID")
    mode: ReportStage = Field(default=ReportStage.AUDIT, description="Generation mode")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")
    language: str = Field(default="fr", regex="^(fr|en)$", description="Output language")


class BulkActionRequest(BaseModel):
    """Bulk action request model"""
    vuln_ids: List[int] = Field(..., min_items=1, max_items=100, description="List of vulnerability IDs")
    action: str = Field(..., regex="^(generate_playbook|mark_resolved|archive)$", description="Action to perform")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Action parameters")


class MLModelUpdateRequest(BaseModel):
    """ML model update request model"""
    model_type: str = Field(..., regex="^(regression|classification)$", description="Model type")
    retrain: bool = Field(default=False, description="Whether to retrain the model")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Model parameters")


class KnowledgeBaseQueryRequest(BaseModel):
    """Knowledge base query request model"""
    query: str = Field(..., min_length=3, max_length=500, description="Search query")
    top_k: int = Field(default=5, ge=1, le=20, description="Number of results")
    filters: Optional[Dict[str, Any]] = Field(None, description="Search filters")


# ============================================================================
# RESPONSE MODELS
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Check timestamp")
    services: Dict[str, str] = Field(..., description="Individual service statuses")
    version: str = Field(..., description="API version")


class StatsResponse(BaseModel):
    """Global statistics response model"""
    total_vulns: int = Field(..., ge=0, description="Total vulnerabilities")
    total_hosts: int = Field(..., ge=0, description="Total hosts")
    total_reports: int = Field(..., ge=0, description="Total reports")
    avg_cvss: float = Field(..., ge=0.0, le=10.0, description="Average CVSS score")
    severity_distribution: Dict[str, int] = Field(..., description="Distribution by severity")
    last_scan: Optional[datetime] = Field(None, description="Last scan timestamp")


class VulnerabilityResponse(BaseModel):
    """Vulnerability response model"""
    id: int = Field(..., description="Vulnerability ID")
    cve: Optional[str] = Field(None, description="CVE identifier")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    description: Optional[str] = Field(None, description="Vulnerability description")
    source: VulnerabilitySource = Field(..., description="Data source")
    severity: SeverityLevel = Field(..., description="Severity level")
    ml_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="ML risk score")
    ml_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="ML confidence")
    reasoning: Optional[str] = Field(None, description="ML reasoning")
    exploit_available: bool = Field(default=False, description="Exploit availability")
    exploit_info: Optional[str] = Field(None, description="Exploit information")
    has_report: bool = Field(default=False, description="Report availability")
    host_ip: str = Field(..., description="Host IP address")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Service port")
    service: Optional[str] = Field(None, description="Service name")
    protocol: Optional[str] = Field(None, description="Service protocol")
    version: Optional[str] = Field(None, description="Service version")
    timestamp: datetime = Field(..., description="Discovery timestamp")

    class Config:
        orm_mode = True


class HostResponse(BaseModel):
    """Host response model"""
    id: int = Field(..., description="Host ID")
    ip: str = Field(..., description="IP address")
    hostname: Optional[str] = Field(None, description="Hostname")
    os: Optional[str] = Field(None, description="Operating system")
    ports: List[int] = Field(default_factory=list, description="Open ports")
    vuln_count: int = Field(default=0, ge=0, description="Vulnerability count")
    severity_distribution: Dict[str, int] = Field(default_factory=dict, description="Severity distribution")
    last_scan: Optional[datetime] = Field(None, description="Last scan timestamp")
    timestamp: datetime = Field(..., description="Discovery timestamp")

    class Config:
        orm_mode = True


class ServiceResponse(BaseModel):
    """Service response model"""
    id: int = Field(..., description="Service ID")
    host_id: int = Field(..., description="Host ID")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: Optional[str] = Field(None, description="Protocol")
    service: Optional[str] = Field(None, description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    banner: Optional[str] = Field(None, description="Service banner")
    cpe: Optional[str] = Field(None, description="CPE identifier")
    vuln_count: int = Field(default=0, ge=0, description="Vulnerability count")
    timestamp: datetime = Field(..., description="Discovery timestamp")

    class Config:
        orm_mode = True


class ReportResponse(BaseModel):
    """Report response model"""
    id: int = Field(..., description="Report ID")
    vuln_id: int = Field(..., description="Vulnerability ID")
    title: str = Field(..., description="Report title")
    content_md: Optional[str] = Field(None, description="Markdown content")
    stage: ReportStage = Field(..., description="Report stage")
    vulnerability: Optional[VulnerabilityResponse] = Field(None, description="Associated vulnerability")
    timestamp: datetime = Field(..., description="Creation timestamp")

    class Config:
        orm_mode = True


class MLModelResponse(BaseModel):
    """ML model response model"""
    model_type: str = Field(..., description="Model type")
    version: str = Field(..., description="Model version")
    accuracy: Optional[float] = Field(None, ge=0.0, le=1.0, description="Model accuracy")
    precision: Optional[float] = Field(None, ge=0.0, le=1.0, description="Model precision")
    recall: Optional[float] = Field(None, ge=0.0, le=1.0, description="Model recall")
    f1_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="F1 score")
    last_trained: Optional[datetime] = Field(None, description="Last training timestamp")
    feature_importance: Optional[Dict[str, float]] = Field(None, description="Feature importance")


class PlaybookResponse(BaseModel):
    """Playbook generation response model"""
    report_id: int = Field(..., description="Report ID")
    vuln_id: int = Field(..., description="Vulnerability ID")
    stage: ReportStage = Field(..., description="Generation stage")
    status: str = Field(..., description="Generation status")
    content_preview: Optional[str] = Field(None, max_length=500, description="Content preview")
    generation_time: float = Field(..., ge=0.0, description="Generation time in seconds")
    sources_used: List[str] = Field(default_factory=list, description="Knowledge sources used")
    timestamp: datetime = Field(..., description="Generation timestamp")


class ErrorResponse(BaseModel):
    """Error response model"""
    error_code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")


class PaginatedResponse(BaseModel):
    """Paginated response model"""
    items: List[Any] = Field(..., description="Response items")
    total: int = Field(..., ge=0, description="Total items")
    limit: int = Field(..., ge=1, le=1000, description="Items per page")
    offset: int = Field(..., ge=0, description="Current offset")
    has_next: bool = Field(..., description="Has next page")
    has_prev: bool = Field(..., description="Has previous page")


class BulkActionResponse(BaseModel):
    """Bulk action response model"""
    action: str = Field(..., description="Action performed")
    total_requested: int = Field(..., ge=0, description="Total items requested")
    successful: int = Field(..., ge=0, description="Successful operations")
    failed: int = Field(..., ge=0, description="Failed operations")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Action timestamp")


class KnowledgeBaseResponse(BaseModel):
    """Knowledge base query response model"""
    query: str = Field(..., description="Search query")
    results: List[Dict[str, Any]] = Field(..., description="Search results")
    total_found: int = Field(..., ge=0, description="Total results found")
    search_time: float = Field(..., ge=0.0, description="Search time in seconds")
    sources_queried: List[str] = Field(default_factory=list, description="Sources queried")


class SystemMetricsResponse(BaseModel):
    """System metrics response model"""
    cpu_usage: float = Field(..., ge=0.0, le=100.0, description="CPU usage percentage")
    memory_usage: float = Field(..., ge=0.0, le=100.0, description="Memory usage percentage")
    disk_usage: float = Field(..., ge=0.0, le=100.0, description="Disk usage percentage")
    active_connections: int = Field(..., ge=0, description="Active connections")
    requests_per_second: float = Field(..., ge=0.0, description="Requests per second")
    uptime: float = Field(..., ge=0.0, description="System uptime in seconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Metrics timestamp")