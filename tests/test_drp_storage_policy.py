import pytest

from app.repositories.digital_risk_events import (
    SQLiteDigitalRiskRepository,
    digital_risk_repository,
)


def _clear(monkeypatch):
    for name in (
        "BSA_DRP_REPOSITORY_BACKEND",
        "BSA_DATABASE_URL",
        "BSA_DRP_DB",
        "BSA_ALLOW_LEGACY_STORAGE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_development_defaults_to_sqlite(monkeypatch, tmp_path):
    _clear(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "development")
    monkeypatch.setenv("BSA_DRP_DB", str(tmp_path / "drp.db"))

    repository = digital_risk_repository()

    assert isinstance(repository, SQLiteDigitalRiskRepository)


def test_production_defaults_to_postgres_and_requires_dsn(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")

    with pytest.raises(RuntimeError, match="BSA_DATABASE_URL is required"):
        digital_risk_repository()


@pytest.mark.parametrize("backend", ["legacy", "sqlite"])
def test_production_rejects_legacy_drp_storage(monkeypatch, backend):
    _clear(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_DRP_REPOSITORY_BACKEND", backend)

    with pytest.raises(RuntimeError, match="legacy DRP storage is disabled"):
        digital_risk_repository()


def test_emergency_override_must_be_explicit(monkeypatch, tmp_path):
    _clear(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_DRP_REPOSITORY_BACKEND", "sqlite")
    monkeypatch.setenv("BSA_ALLOW_LEGACY_STORAGE", "1")
    monkeypatch.setenv("BSA_DRP_DB", str(tmp_path / "drp.db"))

    repository = digital_risk_repository()

    assert isinstance(repository, SQLiteDigitalRiskRepository)


def test_sqlite_repository_preserves_tenant_isolation(monkeypatch, tmp_path):
    _clear(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "development")
    monkeypatch.setenv("BSA_DRP_DB", str(tmp_path / "drp.db"))
    repository = digital_risk_repository()

    repository.put("tenant-a", "evt-1", {"event_id": "evt-1", "category": "phishing"}, 1, 2)
    repository.put("tenant-b", "evt-1", {"event_id": "evt-1", "category": "leak"}, 1, 2)

    assert [item["category"] for item in repository.list("tenant-a")] == ["phishing"]
    assert [item["category"] for item in repository.list("tenant-b")] == ["leak"]
