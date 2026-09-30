from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .changes import seed_changes
from .graph import RELATIONSHIPS
from .intelligence import ownership_confidence, blast_radius, finding_context_score
from .models import Dashboard
from .scoring import exposure_score
from .store import ASSETS, FINDINGS

app = FastAPI(
    title="BSA — Be Safe ASM API",
    version="0.2.0",
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
    return {"status": "ok", "product": "BSA", "version": "0.2.0", "powered_by": "Mariana BS"}


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


@app.get("/api/v1/score")
def score():
    result = exposure_score(FINDINGS, ASSETS)
    return {"score": result.score, "penalty": result.penalty, "rationale": result.rationale}


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
