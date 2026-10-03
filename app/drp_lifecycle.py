"""Operational lifecycle helpers for Digital Risk Protection events."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import time

from . import digital_risk


LIFECYCLE_STATES={"new","active","recurring","contained","resolved","resurfaced"}
_ALLOWED_TRANSITIONS={
    "new":{"active","contained","resolved"},
    "active":{"contained","resolved"},
    "recurring":{"active","contained","resolved"},
    "contained":{"active","resolved","resurfaced"},
    "resolved":{"resurfaced"},
    "resurfaced":{"active","contained","resolved"},
}


def lifecycle_summary(events: list[dict]) -> dict:
    by_state={}
    recurring=0
    resurfaced=0
    contained=0
    resolved=0
    for event in events:
        state=str(event.get("lifecycle_state") or "new").strip().lower()
        if state not in LIFECYCLE_STATES:
            state="new"
        by_state[state]=by_state.get(state,0)+1
        recurring+=int(bool(event.get("recurring")) or state=="recurring")
        resurfaced+=int(state=="resurfaced")
        contained+=int(state=="contained")
        resolved+=int(state=="resolved")
    return {
        "by_lifecycle":by_state,
        "recurring":recurring,
        "resurfaced":resurfaced,
        "contained":contained,
        "resolved":resolved,
    }


def update_event_lifecycle(tenant_id: str, event_id: str, new_state: str) -> dict | None:
    state=str(new_state or "").strip().lower()
    if state not in LIFECYCLE_STATES:
        raise ValueError("invalid digital risk lifecycle state")

    conn=digital_risk._db()
    try:
        row=conn.execute(
            "SELECT payload,created_at FROM digital_risk WHERE tenant_id=? AND event_id=?",
            (tenant_id,event_id),
        ).fetchone()
        if not row:
            return None
        event=json.loads(row["payload"])
        current=str(event.get("lifecycle_state") or "new").strip().lower()
        if current not in LIFECYCLE_STATES:
            current="new"
        if state!=current and state not in _ALLOWED_TRANSITIONS[current]:
            raise ValueError(f"invalid lifecycle transition: {current} -> {state}")

        now_iso=datetime.now(timezone.utc).isoformat()
        history=list(event.get("lifecycle_history") or [])[-49:]
        if state!=current:
            history.append({"from":current,"to":state,"at":now_iso})
        status="resolved" if state=="resolved" else "contained" if state=="contained" else "open"
        event={
            **event,
            "lifecycle_state":state,
            "lifecycle_history":history,
            "lifecycle_changed_at":now_iso,
            "status":status,
        }
        event=digital_risk.enrich_event(event)
        now=int(time.time())
        conn.execute(
            "UPDATE digital_risk SET payload=?, updated_at=? WHERE tenant_id=? AND event_id=?",
            (json.dumps(event,ensure_ascii=False),now,tenant_id,event_id),
        )
        conn.commit()
        return event
    finally:
        conn.close()
