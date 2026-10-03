import pytest

from app.repositories.assets_findings import AssetFindingRepository, asset_finding_repository


def _clear_storage_env(monkeypatch):
    for name in (
        "BSA_ASSET_REPOSITORY_BACKEND",
        "BSA_DATABASE_URL",
        "BSA_ALLOW_LEGACY_STORAGE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_development_keeps_legacy_default(monkeypatch):
    _clear_storage_env(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "development")

    repository = asset_finding_repository()

    assert isinstance(repository, AssetFindingRepository)


def test_production_defaults_to_postgres_and_requires_dsn(monkeypatch):
    _clear_storage_env(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")

    with pytest.raises(RuntimeError, match="BSA_DATABASE_URL is required"):
        asset_finding_repository()


@pytest.mark.parametrize("backend", ["legacy", "sqlite", "memory"])
def test_production_rejects_legacy_backends(monkeypatch, backend):
    _clear_storage_env(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_ASSET_REPOSITORY_BACKEND", backend)

    with pytest.raises(RuntimeError, match="legacy asset storage is disabled"):
        asset_finding_repository()


def test_emergency_override_is_explicit(monkeypatch):
    _clear_storage_env(monkeypatch)
    monkeypatch.setenv("BSA_ENV", "production")
    monkeypatch.setenv("BSA_ASSET_REPOSITORY_BACKEND", "legacy")
    monkeypatch.setenv("BSA_ALLOW_LEGACY_STORAGE", "1")

    repository = asset_finding_repository()

    assert isinstance(repository, AssetFindingRepository)
