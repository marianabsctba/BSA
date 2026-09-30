from fastapi import FastAPI
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
def list_assets():
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
def list_findings():
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        item = finding.model_dump()
        asset = asset_map.get(finding.asset_id)
        item["context_score"] = finding_context_score(finding, asset) if asset else None
        result.append(item)
    return result


@app.get("/api/v1/changes")
def list_changes():
    return seed_changes(ASSETS)


@app.get("/api/v1/graph")
def graph():
    return RELATIONSHIPS


class DiscoveryRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    checks: list[str] = Field(default_factory=lambda: ["dns", "http", "tls", "ct"])


@app.get("/api/v1/score")
def score():
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
def discovery(request: DiscoveryRequest):
    allowed = {"dns", "http", "tls", "ct"}
    checks = list(dict.fromkeys(request.checks))
    if not checks or any(check not in allowed for check in checks):
        raise HTTPException(status_code=400, detail="checks deve conter apenas dns, http, tls e ct")
    try:
        return collect_target(request.target, checks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/discovery/{target}/changes")
def discovery_changes(target: str):
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
def discovery_graph(target: str):
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    return build_risk_graph(data["target"], assets, data["evidence"], source_assets=ASSETS, findings=FINDINGS)

@app.get("/api/v1/discovery/{target}/correlation")
def discovery_correlation(target: str):
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
def exposure():
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
def dashboard():
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
def discovery_risk_paths(target: str):
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    graph = build_risk_graph(data["target"], assets, data["evidence"], source_assets=ASSETS, findings=FINDINGS)
    return {
        "target": data["target"],
        "paths": graph["top_risk_paths"],
        "summary": graph["risk_summary"],
    }
