from app import auth
from app.tenant_risk_policy import TenantRiskPolicy, policy_for, save_policy


def test_tenant_risk_policy_persists_per_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()

    policy=TenantRiskPolicy(
        tenant_id="tenant-a",
        version=2,
        name="Tenant A Policy",
        likelihood_weight=0.50,
        impact_weight=0.35,
        confidence_weight=0.15,
        internet_multiplier=1.20,
        production_multiplier=1.05,
        remote_access_multiplier=1.15,
        compensating_control_reduction=0.20,
        stale_evidence_days=14,
        stale_confidence_penalty=12,
    )
    save_policy(policy,updated_by="admin-a")

    loaded=policy_for("tenant-a")
    assert loaded==policy

    other=policy_for("tenant-b")
    assert other.tenant_id=="tenant-b"
    assert other.version==1
    assert other.name!="Tenant A Policy"
