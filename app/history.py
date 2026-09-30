from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Observation:
    fingerprint: str
    observed_at: str
    confidence: int
    evidence_count: int


_HISTORY: dict[str, list[Observation]] = {}


def record_observations(assets) -> list[Observation]:
    now = datetime.now(timezone.utc).isoformat()
    observations = []
    for asset in assets:
        obs = Observation(asset.fingerprint, now, asset.confidence, asset.evidence_count)
        _HISTORY.setdefault(asset.fingerprint, []).append(obs)
        observations.append(obs)
    return observations


def history_for(fingerprint: str) -> list[Observation]:
    return list(_HISTORY.get(fingerprint, []))


def change_summary(fingerprint: str) -> dict:
    history = history_for(fingerprint)
    if not history:
        return {"state": "new", "observations": 0, "confidence_delta": 0}
    delta = history[-1].confidence - history[0].confidence
    return {
        "state": "new" if len(history) == 1 else "observed",
        "observations": len(history),
        "confidence_delta": delta,
        "first_seen": history[0].observed_at,
        "last_seen": history[-1].observed_at,
    }
