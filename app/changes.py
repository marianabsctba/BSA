from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Change:
    id: str
    asset_id: str
    kind: str
    summary: str
    risk_delta: int
    observed_at: str
    evidence: tuple[str, ...] = ()


def seed_changes(assets: list) -> list[Change]:
    changes: list[Change] = []
    for idx, asset in enumerate(assets, start=1):
        if "new" in asset.tags:
            changes.append(Change(
                id=f"chg-{idx:03d}",
                asset_id=asset.id,
                kind="new_asset",
                summary=f"Novo ativo observado: {asset.value}",
                risk_delta=12 if asset.criticality >= 4 else 5,
                observed_at=asset.last_seen,
                evidence=("asset tagged new",),
            ))
        if "changed" in asset.tags:
            changes.append(Change(
                id=f"chg-{idx+100:03d}",
                asset_id=asset.id,
                kind="service_change",
                summary=f"Mudança relevante detectada em {asset.value}",
                risk_delta=8,
                observed_at=asset.last_seen,
                evidence=("asset tagged changed",),
            ))
    return changes
