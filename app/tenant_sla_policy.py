from dataclasses import dataclass, asdict
import json
import time

from .auth import _db


@dataclass(frozen=True)
class TenantSLAPolicy:
    tenant_id: str
    critical_hours: int = 24
    high_hours: int = 48
    medium_hours: int = 168
    low_hours: int = 336
    version: int = 1


def _ensure_schema() -> None:
    conn=_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS tenant_sla_policies(
        tenant_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        policy_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by TEXT
    )""")
    conn.commit()
    conn.close()


def validate_sla_policy(policy: TenantSLAPolicy) -> list[str]:
    errors=[]
    values=[
        policy.critical_hours,
        policy.high_hours,
        policy.medium_hours,
        policy.low_hours,
    ]
    if any(int(v)<1 or int(v)>8760 for v in values):
        errors.append("SLA thresholds must be between 1 and 8760 hours")
    if not (
        policy.critical_hours <= policy.high_hours
        <= policy.medium_hours <= policy.low_hours
    ):
        errors.append("SLA thresholds must increase from critical to low")
    return errors


def sla_policy_for(tenant_id: str) -> TenantSLAPolicy:
    conn=_db()
    row=conn.execute(
        "SELECT version,policy_json FROM tenant_sla_policies WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()
    conn.close()
    if not row:
        return TenantSLAPolicy(tenant_id=tenant_id)
    try:
        payload=json.loads(row["policy_json"])
        return TenantSLAPolicy(
            tenant_id=tenant_id,
            version=int(row["version"]),
            critical_hours=int(payload.get("critical_hours",24)),
            high_hours=int(payload.get("high_hours",48)),
            medium_hours=int(payload.get("medium_hours",168)),
            low_hours=int(payload.get("low_hours",336)),
        )
    except (TypeError,ValueError,json.JSONDecodeError):
        return TenantSLAPolicy(tenant_id=tenant_id)


def save_sla_policy(policy: TenantSLAPolicy, updated_by: str | None=None) -> TenantSLAPolicy:
    errors=validate_sla_policy(policy)
    if errors:
        raise ValueError("; ".join(errors))
    payload={
        "critical_hours":int(policy.critical_hours),
        "high_hours":int(policy.high_hours),
        "medium_hours":int(policy.medium_hours),
        "low_hours":int(policy.low_hours),
    }
    _ensure_schema()
    conn=_db()
    conn.execute(
        """INSERT INTO tenant_sla_policies(tenant_id,version,policy_json,updated_at,updated_by)
           VALUES(?,?,?,?,?)
           ON CONFLICT(tenant_id) DO UPDATE SET
             version=excluded.version,
             policy_json=excluded.policy_json,
             updated_at=excluded.updated_at,
             updated_by=excluded.updated_by""",
        (
            policy.tenant_id,
            int(policy.version),
            json.dumps(payload,sort_keys=True,separators=(",",":")),
            int(time.time()),
            updated_by,
        ),
    )
    conn.commit()
    conn.close()
    return policy


def sla_threshold_hours(priority: int, policy: TenantSLAPolicy) -> int:
    value=int(priority or 0)
    if value>=85:
        return policy.critical_hours
    if value>=70:
        return policy.high_hours
    if value>=45:
        return policy.medium_hours
    return policy.low_hours


def serialize_sla_policy(policy: TenantSLAPolicy) -> dict:
    return asdict(policy)
