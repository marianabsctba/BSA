from app import auth
from app.policy_service import (
    build_and_save_risk_policy,
    build_and_save_sla_policy,
    get_risk_policy_view,
    get_sla_policy_view,
)


def test_policy_service_persists_risk_and_sla(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    auth._run_one_time_migrations(conn)
    conn.close()

    risk=build_and_save_risk_policy(
        "tenant-a",
        "admin-a",
        {
            "name":"Tenant A",
            "likelihood_weight":0.5,
            "impact_weight":0.35,
            "confidence_weight":0.15,
        },
    )
    assert risk.version==2
    assert get_risk_policy_view("tenant-a")["policy"]["name"]=="Tenant A"

    sla=build_and_save_sla_policy(
        "tenant-a",
        "admin-a",
        critical_hours=8,
        high_hours=24,
        medium_hours=72,
        low_hours=240,
    )
    assert sla.version==2
    assert get_sla_policy_view("tenant-a")["policy"]["critical_hours"]==8
