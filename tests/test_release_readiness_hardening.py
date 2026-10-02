import app.release_readiness as rr


def _engine_health_ready():
    return {
        "profiles": {
            "rapid": {"ready": True, "coverage_percent": 100},
            "balanced": {"ready": True, "coverage_percent": 100},
        }
    }


def test_production_readiness_blocks_unsafe_runtime(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setenv("BSA_JWT_SECRET","x"*40)
    monkeypatch.setenv("BSA_AUTH_DB","/data/auth.db")
    monkeypatch.setenv("BSA_HISTORY_DB","/data/history.db")
    monkeypatch.setenv("BSA_STORE_DB","/data/store.db")
    monkeypatch.setenv("BSA_JOBS_DB","/data/jobs.db")
    monkeypatch.setenv("BSA_DEMO_DATA","1")
    monkeypatch.delenv("BSA_ALLOWED_ORIGINS",raising=False)
    monkeypatch.delenv("BSA_ALLOWED_HOSTS",raising=False)

    monkeypatch.setattr(rr,"engine_health",_engine_health_ready)
    monkeypatch.setattr(rr,"_store_path",lambda: "/data/store.db")
    monkeypatch.setattr(rr,"_db_path",lambda: "/data/jobs.db")
    monkeypatch.setattr(rr,"ensure_authorization_schema",lambda: None)
    monkeypatch.setattr(rr,"get_retention_policy",lambda tenant_id: {"retention_days":180})

    result=rr.release_readiness()
    assert result["state"]=="blocked"
    assert "demo_data_disabled" in result["required_failures"]
    assert "origin_policy" in result["required_failures"]
    assert "host_policy" in result["required_failures"]


def test_production_readiness_passes_required_governance_checks(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setenv("BSA_JWT_SECRET","y"*40)
    monkeypatch.setenv("BSA_AUTH_DB","/data/auth.db")
    monkeypatch.setenv("BSA_HISTORY_DB","/data/history.db")
    monkeypatch.setenv("BSA_STORE_DB","/data/store.db")
    monkeypatch.setenv("BSA_JOBS_DB","/data/jobs.db")
    monkeypatch.setenv("BSA_DEMO_DATA","0")
    monkeypatch.setenv("BSA_ALLOWED_ORIGINS","https://asm.example.org")
    monkeypatch.setenv("BSA_ALLOWED_HOSTS","asm.example.org")

    monkeypatch.setattr(rr,"engine_health",_engine_health_ready)
    monkeypatch.setattr(rr,"_store_path",lambda: "/data/store.db")
    monkeypatch.setattr(rr,"_db_path",lambda: "/data/jobs.db")
    monkeypatch.setattr(rr,"ensure_authorization_schema",lambda: None)
    monkeypatch.setattr(rr,"get_retention_policy",lambda tenant_id: {"retention_days":180})

    result=rr.release_readiness()
    assert result["required_failures"]==[]
    names={x["name"]:x["status"] for x in result["checks"]}
    assert names["persistent_history_store"]=="pass"
    assert names["demo_data_disabled"]=="pass"
    assert names["origin_policy"]=="pass"
    assert names["host_policy"]=="pass"
    assert names["tenant_retention_policy"]=="pass"
    assert names["scan_authorization_store"]=="pass"
