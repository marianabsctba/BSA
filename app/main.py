from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .changes import seed_changes
from .graph import RELATIONSHIPS, build_attack_surface_graph, build_risk_graph
from .intelligence import ownership_confidence, blast_radius, finding_context_score
from .models import Dashboard
from .scoring import exposure_score
from .exposure import exposure_breakdown, exposure_band
from .discovery import collect_target
from fastapi import HTTPException
from pydantic import BaseModel, Field
from .store import ASSETS, FINDINGS
from .correlation import correlate_evidence
from .history import record_observations, change_summary
from .prioritization import prioritize_finding
from .remediation import build_remediation_plan
from .auth import authenticate, bootstrap, can, create_user, list_users, principal_from_token

bootstrap()

app = FastAPI(
    title="BSA — Be Safe ASM API",
    version="0.3.0",
    description="Attack Surface Management defensivo, rastreável e orientado a evidências.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "product": "BSA", "version": "0.3.0", "powered_by": "Mariana BS"}


@app.get("/api/v1/assets")
def list_assets(request: Request):
    require(request, "assets:read")
    result = []
    for asset in ASSETS:
        item = asset.model_dump()
        ownership = ownership_confidence(asset)
        item["ownership"] = {
            "score": ownership.score,
            "state": ownership.state,
            "reasons": ownership.reasons,
        }
        item["blast_radius"] = blast_radius(asset)
        result.append(item)
    return result


@app.get("/api/v1/findings")
def list_findings(request: Request):
    require(request, "findings:read")
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        item = finding.model_dump()
        asset = asset_map.get(finding.asset_id)
        item["context_score"] = finding_context_score(finding, asset) if asset else None
        result.append(item)
    return result


@app.get("/api/v1/changes")
def list_changes(request: Request):
    require(request, "assets:read")
    return seed_changes(ASSETS)


@app.get("/api/v1/graph")
def graph():
    return RELATIONSHIPS




class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=256)

class UserCreateRequest(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: str


def current_principal(request: Request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="authentication required")
    try:
        return principal_from_token(header[7:])
    except Exception as exc:
        raise HTTPException(status_code=401, detail="invalid or expired token") from exc


def require(request: Request, permission: str):
    principal = current_principal(request)
    if not can(principal, permission):
        raise HTTPException(status_code=403, detail="permission denied")
    return principal


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest):
    token = authenticate(payload.email, payload.password)
    if not token:
        raise HTTPException(status_code=401, detail="invalid credentials")
    principal = principal_from_token(token)
    return {"access_token": token, "token_type": "bearer", "expires_in": 28800, "user": {"id": principal.user_id, "email": principal.email, "name": principal.name, "role": principal.role, "tenant_id": principal.tenant_id}}


@app.get("/api/v1/auth/me")
def me(request: Request):
    p = current_principal(request)
    return {"id": p.user_id, "email": p.email, "name": p.name, "role": p.role, "tenant_id": p.tenant_id}


@app.get("/api/v1/users")
def users(request: Request):
    p = require(request, "users:read")
    try:
        return list_users(p)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/users")
def users_create(request: Request, payload: UserCreateRequest):
    p = current_principal(request)
    if p.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    try:
        return create_user(p, payload.email, payload.name, payload.password, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=409, detail="user already exists or invalid data") from exc


class DiscoveryRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    checks: list[str] = Field(default_factory=lambda: ["dns", "http", "tls", "ct"])


@app.get("/api/v1/score")
def score(request: Request):
    require(request, "assets:read")
    result = exposure_score(FINDINGS, ASSETS)
    breakdowns = []
    for asset in ASSETS:
        item = exposure_breakdown(asset, FINDINGS)
        breakdowns.append({
            "asset_id": asset.id,
            "asset": asset.value,
            "score": item.score,
            "band": exposure_band(item.score),
            "rationale": item.rationale,
            "dimensions": {
                "internet": item.internet,
                "exploitability": item.exploitability,
                "criticality": item.criticality,
                "intelligence": item.intelligence,
                "confidence": item.confidence,
                "shadow": item.shadow,
            },
        })
    return {
        "score": result.score,
        "penalty": result.penalty,
        "rationale": result.rationale,
        "assets": breakdowns,
    }


@app.post("/api/v1/discovery")
def discovery(request: DiscoveryRequest, http_request: Request):
    require(http_request, "discovery:run")
    allowed = {"dns", "http", "tls", "ct"}
    checks = list(dict.fromkeys(request.checks))
    if not checks or any(check not in allowed for check in checks):
        raise HTTPException(status_code=400, detail="checks deve conter apenas dns, http, tls e ct")
    try:
        return collect_target(request.target, checks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/discovery/{target}/changes")
def discovery_changes(target: str, request: Request):
    require(request, "assets:read")
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    record_observations(assets)
    return {
        "target": data["target"],
        "changes": [
            {
                "fingerprint": asset.fingerprint,
                "asset": asset.value,
                "type": asset.asset_type,
                "change": change_summary(asset.fingerprint),
            }
            for asset in assets
        ],
    }


@app.get("/api/v1/discovery/{target}/graph")
def discovery_graph(target: str, request: Request):
    require(request, "assets:read")
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    return build_risk_graph(data["target"], assets, data["evidence"], source_assets=ASSETS, findings=FINDINGS)

@app.get("/api/v1/discovery/{target}/correlation")
def discovery_correlation(target: str, request: Request):
    require(request, "assets:read")
    """Return normalized asset identities for an explicit discovery target."""
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    observations = record_observations(assets)
    return {
        "target": data["target"],
        "evidence_count": data["evidence_count"],
        "confidence": data["confidence"],
        "assets": [
            {
                "fingerprint": asset.fingerprint,
                "value": asset.value,
                "type": asset.asset_type,
                "confidence": asset.confidence,
                "sources": list(asset.sources),
                "evidence_count": asset.evidence_count,
                "tags": list(asset.tags),
                "history": change_summary(asset.fingerprint),
            }
            for asset in assets
        ],
        "observation_count": len(observations),
    }


@app.get("/api/v1/exposure")
def exposure(request: Request):
    require(request, "assets:read")
    items = []
    for asset in ASSETS:
        item = exposure_breakdown(asset, FINDINGS)
        items.append({
            "asset_id": asset.id,
            "asset": asset.value,
            "score": item.score,
            "band": exposure_band(item.score),
            "rationale": item.rationale,
            "dimensions": {
                "internet": item.internet,
                "exploitability": item.exploitability,
                "criticality": item.criticality,
                "intelligence": item.intelligence,
                "confidence": item.confidence,
                "shadow": item.shadow,
            },
        })
    return sorted(items, key=lambda x: x["score"], reverse=True)


@app.get("/api/v1/dashboard", response_model=Dashboard)
def dashboard(request: Request):
    require(request, "assets:read")
    changes = seed_changes(ASSETS)
    ownership = [ownership_confidence(a) for a in ASSETS]
    score = exposure_score(FINDINGS, ASSETS)

    return Dashboard(
        total_assets=len(ASSETS),
        exposed_services=sum(1 for a in ASSETS if a.type.value == "service"),
        open_findings=sum(1 for f in FINDINGS if f.status == "open"),
        critical_findings=sum(1 for f in FINDINGS if f.status == "open" and f.severity.value == "critical"),
        exposure_score=score.score,
        confirmed_assets=sum(1 for o in ownership if o.state == "confirmed"),
        candidate_assets=sum(1 for o in ownership if o.state == "candidate"),
        changes_24h=len(changes),
        attack_paths=len(RELATIONSHIPS),
    )

@app.get("/api/v1/discovery/{target}/risk-paths")
def discovery_risk_paths(target: str, request: Request):
    require(request, "assets:read")
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    graph = build_risk_graph(data["target"], assets, data["evidence"], source_assets=ASSETS, findings=FINDINGS)
    return {
        "target": data["target"],
        "paths": graph["top_risk_paths"],
        "summary": graph["risk_summary"],
    }


@app.get("/api/v1/prioritization")
def prioritization(request: Request):
    require(request, "findings:read")
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        asset = asset_map.get(finding.asset_id)
        item = prioritize_finding(finding, asset)
        result.append({
            "finding_id": finding.id,
            "finding": finding.title,
            "asset": asset.value if asset else None,
            "priority": item.priority,
            "score": item.score,
            "impact": item.impact,
            "urgency": item.urgency,
            "confidence": item.confidence,
            "reasons": item.reasons,
            "recommended_action": item.action,
        })
    return sorted(result, key=lambda x: (-x["score"], x["priority"]))


@app.get("/api/v1/remediation")
def remediation(request: Request):
    require(request, "remediation:write")
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        asset = asset_map.get(finding.asset_id)
        if not asset or finding.status != "open":
            continue
        plan = build_remediation_plan(finding, asset)
        result.append({
            "finding_id": plan.finding_id,
            "asset_id": plan.asset_id,
            "asset": asset.value,
            "priority": plan.priority,
            "current_score": plan.current_score,
            "residual_score": plan.residual_score,
            "risk_reduction": plan.risk_reduction,
            "action": plan.action,
            "validation": plan.validation,
            "owner": plan.owner,
            "effort": plan.effort,
            "rationale": plan.rationale,
        })
    return sorted(result, key=lambda x: (-x["risk_reduction"], x["residual_score"]))
