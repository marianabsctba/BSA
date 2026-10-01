"""Be Safe ASM CTEM pipeline.

Transforms exposure intelligence into contextual remediation actions.
The user-facing layer never exposes internal assessment providers.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import uuid


@dataclass(frozen=True)
class CTEMAction:
    action_id: str
    asset: str
    priority: str
    objective: str
    evidence_count: int
    status: str
    created_at: str


def create_action(exposure: dict) -> dict:
    """Create a remediation workflow item from exposure intelligence."""
    risk = int(exposure.get("risk_score", 0))

    if risk >= 90:
        priority = "critical"
    elif risk >= 70:
        priority = "high"
    elif risk >= 40:
        priority = "medium"
    else:
        priority = "low"

    action = CTEMAction(
        action_id=str(uuid.uuid4()),
        asset=exposure.get("asset", "unknown"),
        priority=priority,
        objective="Reduce confirmed exposure risk",
        evidence_count=len(exposure.get("evidence", [])),
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    return asdict(action)
