from app.release_readiness import release_readiness


def _queue_healthy():
    return {
        "status":"healthy",
        "oldest_queued_age_seconds":0,
        "expired_running_leases":0,
        "stale_materializations":0,
        "retry_pressure_jobs":0,
    }


def _worker_healthy():
    return {
        "status":"healthy",
        "workers":1,
        "active_workers":1,
        "stale_workers":0,
        "last_seen_age_seconds":5,
    }


def _engine_state(rapid_ready=True, balanced_ready=True):
    return {
        "profiles": {
            "rapid": {"ready": rapid_ready, "coverage_percent": 100 if rapid_ready else 67},
            "balanced": {"ready": balanced_ready, "coverage_percent": 100 if balanced_ready else 75},
        }
    }


def _governance_ready(monkeypatch):
    monkeypatch.setenv("BSA_HISTORY_DB", "/data/bsa_history.db")
    monkeypatch.setenv("BSA_DEMO_DATA", "0")
    monkeypatch.setattr("app.release_readiness.ensure_authorization_schema", lambda: None)
    monkeypatch.setattr(
        "app.release_readiness.get_retention_policy",
        lambda tenant_id: {"retention_days": 180},
    )
    monkeypatch.setattr("app.release_readiness.queue_health", lambda: _queue_healthy())
    monkeypatch.setattr("app.release_readiness.worker_health", lambda: _worker_healthy())


def test_release_readiness_blocks_without_persistent_security(monkeypatch):
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_JWT_SECRET", "short")
    monkeypatch.setenv("BSA_AUTH_DB", "/tmp/bsa_auth.db")
    monkeypatch.setattr("app.release_readiness._store_path", lambda: None)
    monkeypatch.setattr("app.release_readiness._db_path", lambda: "/tmp/bsa_jobs.db")
    monkeypatch.setattr("app.release_readiness.engine_health", lambda: _engine_state())

    data = release_readiness()

    assert data["state"] == "blocked"
    assert data["pilot_ready"] is False
    assert "persistent_asset_store" in data["required_failures"]
    assert "strong_auth_secret" in data["required_failures"]


def test_release_readiness_allows_degraded_pilot_with_partial_engines(monkeypatch):
    _governance_ready(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("BSA_AUTH_DB", "/data/bsa_auth.db")
    monkeypatch.setenv("BSA_ALLOWED_ORIGINS", "https://asm.example.com")
    monkeypatch.setenv("BSA_ALLOWED_HOSTS", "asm.example.com")
    monkeypatch.setattr("app.release_readiness._store_path", lambda: "/data/bsa_store.db")
    monkeypatch.setattr("app.release_readiness._db_path", lambda: "/data/bsa_jobs.db")
    monkeypatch.setattr("app.release_readiness.engine_health", lambda: _engine_state(True, False))

    data = release_readiness()

    assert data["state"] == "degraded"
    assert data["pilot_ready"] is True
    assert not data["required_failures"]


def test_release_readiness_ready_when_required_controls_and_coverage_pass(monkeypatch):
    _governance_ready(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("BSA_AUTH_DB", "/data/bsa_auth.db")
    monkeypatch.setenv("BSA_ALLOWED_ORIGINS", "https://asm.example.com")
    monkeypatch.setenv("BSA_ALLOWED_HOSTS", "asm.example.com")
    monkeypatch.setattr("app.release_readiness._store_path", lambda: "/data/bsa_store.db")
    monkeypatch.setattr("app.release_readiness._db_path", lambda: "/data/bsa_jobs.db")
    monkeypatch.setattr("app.release_readiness.engine_health", lambda: _engine_state(True, True))

    data = release_readiness()

    assert data["state"] == "ready"
    assert data["pilot_ready"] is True
    assert data["warnings"] == []


def test_release_readiness_warns_on_degraded_queue(monkeypatch):
    _governance_ready(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("BSA_AUTH_DB", "/data/bsa_auth.db")
    monkeypatch.setenv("BSA_ALLOWED_ORIGINS", "https://asm.example.com")
    monkeypatch.setenv("BSA_ALLOWED_HOSTS", "asm.example.com")
    monkeypatch.setattr("app.release_readiness._store_path", lambda: "/data/bsa_store.db")
    monkeypatch.setattr("app.release_readiness._db_path", lambda: "/data/bsa_jobs.db")
    monkeypatch.setattr("app.release_readiness.engine_health", lambda: _engine_state(True, True))
    monkeypatch.setattr(
        "app.release_readiness.queue_health",
        lambda: {
            "status":"degraded",
            "oldest_queued_age_seconds":1200,
            "expired_running_leases":1,
            "stale_materializations":1,
            "retry_pressure_jobs":2,
        },
    )

    data=release_readiness()

    assert data["state"]=="degraded"
    assert data["pilot_ready"] is True
    assert "assessment_queue_health" in data["warnings"]


def test_release_readiness_warns_on_stale_worker(monkeypatch):
    _governance_ready(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("BSA_AUTH_DB", "/data/bsa_auth.db")
    monkeypatch.setenv("BSA_ALLOWED_ORIGINS", "https://asm.example.com")
    monkeypatch.setenv("BSA_ALLOWED_HOSTS", "asm.example.com")
    monkeypatch.setattr("app.release_readiness._store_path", lambda: "/data/bsa_store.db")
    monkeypatch.setattr("app.release_readiness._db_path", lambda: "/data/bsa_jobs.db")
    monkeypatch.setattr("app.release_readiness.engine_health", lambda: _engine_state(True, True))
    monkeypatch.setattr(
        "app.release_readiness.worker_health",
        lambda: {
            "status":"degraded",
            "workers":1,
            "active_workers":0,
            "stale_workers":1,
            "last_seen_age_seconds":600,
        },
    )

    data=release_readiness()

    assert data["state"]=="degraded"
    assert data["pilot_ready"] is True
    assert "assessment_worker_health" in data["warnings"]
