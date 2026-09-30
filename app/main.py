from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .models import Dashboard
from .store import ASSETS, FINDINGS

app = FastAPI(
    title="BSA — Be Safe ASM API",
    version="0.1.0",
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
    return {"status": "ok", "product": "BSA", "powered_by": "Mariana BS"}


@app.get("/api/v1/assets")
def list_assets():
    return ASSETS


@app.get("/api/v1/findings")
def list_findings():
    return FINDINGS


@app.get("/api/v1/dashboard", response_model=Dashboard)
def dashboard():
    sev = [f.severity.value for f in FINDINGS if f.status == "open"]
    critical = sum(1 for s in sev if s == "critical")
    high = sum(1 for s in sev if s == "high")
    medium = sum(1 for s in sev if s == "medium")

    # Explicável por design: peso simples no MVP; será substituído por engine contextual.
    risk_points = critical * 24 + high * 14 + medium * 7
    exposure_score = max(0, 100 - min(100, risk_points))

    return Dashboard(
        total_assets=len(ASSETS),
        exposed_services=sum(1 for a in ASSETS if a.type.value == "service"),
        open_findings=sum(1 for f in FINDINGS if f.status == "open"),
        critical_findings=critical,
        exposure_score=exposure_score,
    )
