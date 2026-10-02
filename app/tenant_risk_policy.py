from dataclasses import dataclass, asdict, fields
import json
import time

from .auth import _db
from .risk_policy import RiskPolicy, DEFAULT_POLICY
from .risk_engine import assess_risk
from .models import Finding, Asset


@dataclass(frozen=True)
class TenantRiskPolicy(RiskPolicy):
    tenant_id: str = "tenant-demo"
    version: int = 1


def _ensure_policy_schema() -> None:
    conn=_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS tenant_risk_policies(
        tenant_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        policy_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by TEXT
    )""")
    conn.commit()
    conn.close()


def policy_for(tenant_id: str) -> TenantRiskPolicy:
    _ensure_policy_schema()
    conn=_db()
    row=conn.execute(
        "SELECT version,policy_json FROM tenant_risk_policies WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()
    conn.close()
    if not row:
        return TenantRiskPolicy(tenant_id=tenant_id)
    try:
        payload=json.loads(row["policy_json"])
    except (TypeError,ValueError,json.JSONDecodeError):
        return TenantRiskPolicy(tenant_id=tenant_id)
    allowed={f.name for f in fields(RiskPolicy)}
    values={k:payload[k] for k in allowed if k in payload}
    return TenantRiskPolicy(**values,tenant_id=tenant_id,version=int(row["version"]))


def save_policy(policy: TenantRiskPolicy, updated_by: str | None=None) -> TenantRiskPolicy:
    errors=validate_policy(policy)
    if errors:
        raise ValueError("; ".join(errors))
    _ensure_policy_schema()
    payload=serialize_policy(policy)
    payload.pop("tenant_id",None)
    payload.pop("version",None)
    conn=_db()
    conn.execute(
        """INSERT INTO tenant_risk_policies(tenant_id,version,policy_json,updated_at,updated_by)
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


def serialize_policy(policy: TenantRiskPolicy) -> dict:
    return asdict(policy)


def validate_policy(policy: TenantRiskPolicy) -> list[str]:
    errors=[]
    for name in ("likelihood_weight","impact_weight","confidence_weight"):
        value=getattr(policy,name)
        if value<0 or value>1:
            errors.append(name+" must be between 0 and 1")
    total=policy.likelihood_weight+policy.impact_weight+policy.confidence_weight
    if abs(total-1)>0.001:
        errors.append("risk weights must sum to 1")
    for name in (
        "internet_multiplier",
        "production_multiplier",
        "remote_access_multiplier",
        "compensating_control_reduction",
    ):
        value=getattr(policy,name)
        if value<0 or value>2:
            errors.append(name+" outside allowed range")
    if policy.stale_evidence_days<1 or policy.stale_evidence_days>3650:
        errors.append("stale_evidence_days outside allowed range")
    if policy.stale_confidence_penalty<0 or policy.stale_confidence_penalty>100:
        errors.append("stale_confidence_penalty outside allowed range")
    return errors
