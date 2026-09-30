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
    tags: list[str] = []
    first_seen: str
    last_seen: str


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
