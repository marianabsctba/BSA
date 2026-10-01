from enum import Enum
from pydantic import BaseModel, Field


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    SERVICE = "service"
    APPLICATION = "application"
    CERTIFICATE = "certificate"
    CLOUD = "cloud"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Asset(BaseModel):
    tenant_id: str = "tenant-demo"
    id: str
    value: str
    type: AssetType
    status: str = "observed"
    confidence: int = Field(default=80, ge=0, le=100)
    criticality: int = Field(default=3, ge=1, le=5)
    source: str = "manual"
    owner: str | None = None
    business_unit: str | None = None
    environment: str = "unknown"
    cloud_provider: str | None = None
    tags: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    fingerprint: str | None = None
    evidence_count: int = 0
    sources: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    tenant_id: str = "tenant-demo"
    id: str
    asset_id: str
    title: str
    severity: Severity
    confidence: int = Field(default=80, ge=0, le=100)
    status: str = "open"
    evidence: str
    remediation: str | None = None
    vulnerability_id: str | None = None
    cpe: str | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    kev: bool = False
    exploit_available: bool = False
    published_at: str | None = None
    detected_at: str | None = None
    fixed_version: str | None = None
    affected_component: str | None = None
    source_refs: list[str] = Field(default_factory=list)
    false_positive_confidence: int = Field(default=0, ge=0, le=100)
    validation_state: str = "observed"
    evidence_quality: int = Field(default=50, ge=0, le=100)


class Dashboard(BaseModel):
    total_assets: int
    exposed_services: int
    open_findings: int
    critical_findings: int
    exposure_score: int
    confirmed_assets: int
    candidate_assets: int
    changes_24h: int
    attack_paths: int
