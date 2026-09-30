from dataclasses import dataclass
from hashlib import sha256

@dataclass(frozen=True)
class ExposureDNA:
    fingerprint: str
    stability: int
    change_type: str
    signals: list[str]
    material_changes: list[str]
    confidence: int = 0
    explainability: list[str] | None = None

def build_exposure_dna(asset, findings) -> ExposureDNA:
    signals = [
        str(getattr(asset, "type", "")), asset.value, asset.status,
        asset.environment, str(asset.cloud_provider or ""),
        str(asset.owner or ""), str(asset.criticality),
        *sorted(asset.tags),
        *sorted(f"{f.id}:{f.severity}:{f.status}" for f in findings if f.asset_id == asset.id),
    ]
    fp = sha256("|".join(signals).encode()).hexdigest()[:24]
    changes = []
    if "internet-facing" in asset.tags: changes.append("internet-exposed")
    if "new" in asset.tags: changes.append("new-asset")
    if "changed" in asset.tags: changes.append("observed-change")
    if any(f.status == "open" and f.severity.value in {"high","critical"} for f in findings if f.asset_id == asset.id):
        changes.append("high-risk-finding")
    stability = max(0, min(100, asset.confidence - (20 if "candidate" in asset.tags else 0)))
    explainability = [
        f"confidence={asset.confidence}",
        f"evidence_count={getattr(asset, 'evidence_count', 0)}",
        f"criticality={asset.criticality}",
        f"owner={'present' if asset.owner else 'missing'}",
    ]
    return ExposureDNA(fp, stability, "material-change" if changes else "stable", changes, changes, asset.confidence, explainability)
