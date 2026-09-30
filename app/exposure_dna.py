from dataclasses import dataclass, asdict
from hashlib import sha256
import json

@dataclass(frozen=True)
class ExposureDNA:
    fingerprint: str
    stability: int
    change_type: str
    signals: list[str]
    material_changes: list[str]

def build_exposure_dna(asset, findings) -> ExposureDNA:
    signals = [
        str(getattr(asset, "type", "")),
        asset.value,
        asset.status,
        asset.environment,
        str(asset.cloud_provider or ""),
        str(asset.owner or ""),
        str(asset.criticality),
        *sorted(asset.tags),
        *sorted(f"{f.id}:{f.severity}:{f.status}" for f in findings if f.asset_id == asset.id),
    ]
    raw = "|".join(signals)
    fp = sha256(raw.encode()).hexdigest()[:24]
    changes = []
    if "internet-facing" in asset.tags: changes.append("internet-exposed")
    if "new" in asset.tags: changes.append("new-asset")
    if "changed" in asset.tags: changes.append("observed-change")
    if any(f.status == "open" and f.severity.value in {"high","critical"} for f in findings if f.asset_id == asset.id):
        changes.append("high-risk-finding")
    stability = max(0, min(100, asset.confidence - (20 if "candidate" in asset.tags else 0)))
    return ExposureDNA(fp, stability, "material-change" if changes else "stable", changes, changes)
