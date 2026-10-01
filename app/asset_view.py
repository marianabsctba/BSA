from dataclasses import asdict
from .exposure import exposure_breakdown, exposure_band
from .exposure_dna import build_exposure_dna
from .graph import build_risk_graph
from .history import change_summary, history_for
from .intelligence import ownership_confidence, blast_radius, finding_context_score
from .prioritization import prioritize_finding
from .remediation import build_remediation_plan


def asset_detail(asset, findings, all_assets, tenant_id: str):
    asset_findings = [f for f in findings if f.asset_id == asset.id]
    exposure = exposure_breakdown(asset, findings)
    ownership = ownership_confidence(asset)
    dna = build_exposure_dna(asset, findings)
    fingerprint = asset.fingerprint or dna.fingerprint
    plans = [build_remediation_plan(f, asset).__dict__ for f in asset_findings if f.status == "open"]
    graph = build_risk_graph(asset.value, [asset], [], source_assets=all_assets, findings=findings)
    return {
        "asset": asset.model_dump(),
        "ownership": {
            "score": ownership.score,
            "state": ownership.state,
            "reasons": ownership.reasons,
        },
        "blast_radius": blast_radius(asset),
        "risk": {
            "score": exposure.score,
            "band": exposure_band(exposure.score),
            "rationale": exposure.rationale,
            "dimensions": {
                "internet": exposure.internet,
                "exploitability": exposure.exploitability,
                "criticality": exposure.criticality,
                "intelligence": exposure.intelligence,
                "confidence": exposure.confidence,
                "shadow": exposure.shadow,
            },
        },
        "findings": [
            {
                **f.model_dump(),
                "context_score": finding_context_score(f, asset),
                "priority": prioritize_finding(f, asset).priority,
            }
            for f in asset_findings
        ],
        "remediation": plans,
        "history": [h.__dict__ for h in history_for(fingerprint, tenant_id)],
        "change_summary": change_summary(fingerprint, tenant_id),
        "graph": graph,
        "exposure_dna": asdict(dna),
        "evidence": {
            "sources": list(getattr(asset, "sources", ()) or ()),
            "evidence_count": getattr(asset, "evidence_count", 0),
            "tags": list(asset.tags),
        },
    }
