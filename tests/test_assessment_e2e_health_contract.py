from app.assessment_providers import ProviderResult


def test_assessment_execution_persists_runtime_health_end_to_end(tmp_path, monkeypatch):
    from app.assessment_orchestrator import run_assessment
    from app.engine_health import engine_health
    from app import history

    db = tmp_path / "assessment-e2e.db"
    monkeypatch.setenv("BSA_HISTORY_DB", str(db))
    monkeypatch.setenv("BSA_ENV", "development")

    monkeypatch.setattr("app.assessment_orchestrator.PROFILES", {"rapid": ("httpx",)})
    monkeypatch.setattr("app.assessment_orchestrator.PROFILE_CAPABILITIES", {"rapid": ("fingerprint",)})
    monkeypatch.setattr("app.assessment_orchestrator.PROFILE_OPTIONAL_CAPABILITIES", {"rapid": ()})
    monkeypatch.setattr("app.assessment_orchestrator.registry.available", lambda name, target=None: True)
    monkeypatch.setattr(
        "app.assessment_orchestrator.registry.capability_health",
        lambda target=None, capabilities=None: [{
            "name": "fingerprint",
            "status": "ready",
            "operational": True,
            "available_backends": 1,
            "backend_count": 1,
            "backend_coverage_percent": 100,
            "redundant_backends": 0,
        }],
    )
    monkeypatch.setattr(
        "app.assessment_orchestrator.registry.execute",
        lambda name, *, target: [
            ProviderResult(
                "HTTP observed",
                "info",
                92,
                {"url": "https://example.org", "status_code": 200},
            )
        ],
    )

    result = run_assessment("example.org", profile="rapid")

    effectiveness = result["public"]["coverage"]["effectiveness"]
    assert effectiveness["execution_success_percent"] == 100
    assert effectiveness["exercised_capability_percent"] == 100
    assert effectiveness["productive_capability_percent"] == 100
    assert result["public"]["finding_count"] == 1

    persisted = history.recent_capability_execution_health(("fingerprint",), max_age_minutes=60)
    assert persisted[0]["execution_status"] == "verified"
    assert persisted[0]["recent_successful_calls"] >= 1

    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setattr("app.engine_health.PROFILES", {"rapid": ("httpx",)})
    monkeypatch.setattr("app.engine_health.PROFILE_CAPABILITIES", {"rapid": ("fingerprint",)})
    monkeypatch.setattr("app.engine_health.PROFILE_OPTIONAL_CAPABILITIES", {"rapid": ()})
    monkeypatch.setattr(
        "app.engine_health.PROFILE_COVERAGE_POLICY",
        {"rapid": {
            "min_core_coverage_percent": 100,
            "min_backend_coverage_percent": 100,
            "allow_degraded_core": True,
        }},
    )
    monkeypatch.setattr("app.engine_health.registry.available", lambda name, target=None: True)
    monkeypatch.setattr(
        "app.engine_health.registry.capability_health",
        lambda target=None, capabilities=None: [{
            "name": "fingerprint",
            "status": "ready",
            "operational": True,
            "available_backends": 1,
            "backend_count": 1,
            "backend_coverage_percent": 100,
            "redundant_backends": 0,
        }],
    )

    health = engine_health("example.org")["profiles"]["rapid"]

    assert health["ready"] is True
    assert health["state"] == "ready"
    assert health["execution_validation"]["status"] == "verified"
    assert health["readiness_blockers"] == []

    public_text = str(result["public"])
    assert "httpx" not in public_text
    assert "provider" not in public_text.lower()
