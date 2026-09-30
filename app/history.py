from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Observation:
    fingerprint: str
    observed_at: str
    confidence: int
    evidence_count: int
    sources: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


_HISTORY: dict[str, list[Observation]] = {}


def record_observations(assets) -> list[Observation]:
    now = datetime.now(timezone.utc).isoformat()
    observations = []
    for asset in assets:
        obs = Observation(
            asset.fingerprint,
            now,
            asset.confidence,
            asset.evidence_count,
            tuple(asset.sources),
            tuple(asset.tags),
        )
        previous = _HISTORY.setdefault(asset.fingerprint, [])
        if not previous or previous[-1] != obs:
            previous.append(obs)
        observations.append(obs)
    return observations


def history_for(fingerprint: str) -> list[Observation]:
    return list(_HISTORY.get(fingerprint, []))


def change_summary(fingerprint: str) -> dict:
    history = history_for(fingerprint)
    if not history:
        return {"state": "new", "observations": 0, "changes": []}

    changes = []
    if len(history) > 1:
        previous, current = history[-2], history[-1]
        if previous.confidence != current.confidence:
            changes.append({
                "kind": "confidence_change",
                "delta": current.confidence - previous.confidence,
            })
        if previous.evidence_count != current.evidence_count:
            changes.append({
                "kind": "evidence_change",
                "delta": current.evidence_count - previous.evidence_count,
            })
        added_sources = sorted(set(current.sources) - set(previous.sources))
        removed_sources = sorted(set(previous.sources) - set(current.sources))
        if added_sources:
            changes.append({"kind": "source_added", "values": added_sources})
        if removed_sources:
            changes.append({"kind": "source_removed", "values": removed_sources})
        added_tags = sorted(set(current.tags) - set(previous.tags))
        removed_tags = sorted(set(previous.tags) - set(current.tags))
        if added_tags:
            changes.append({"kind": "tag_added", "values": added_tags})
        if removed_tags:
            changes.append({"kind": "tag_removed", "values": removed_tags})

    return {
        "state": "new" if len(history) == 1 else ("changed" if changes else "stable"),
        "observations": len(history),
        "confidence_delta": history[-1].confidence - history[0].confidence,
        "first_seen": history[0].observed_at,
        "last_seen": history[-1].observed_at,
        "changes": changes,
    }


def exposure_snapshot(assets, findings):
    from .exposure import exposure_breakdown
    total = sum(exposure_breakdown(a, findings).score for a in assets)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset_count": len(assets),
        "open_findings": sum(1 for f in findings if f.status == "open"),
        "aggregate_exposure": round(total / len(assets)) if assets else 0,
    }
