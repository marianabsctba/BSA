from pathlib import Path


def test_postgres_overlay_is_opt_in_and_internal():
    base=Path("docker-compose.production.yml").read_text(encoding="utf-8")
    overlay=Path("docker-compose.postgres.yml").read_text(encoding="utf-8")

    assert "BSA_ASSET_REPOSITORY_BACKEND: postgres" not in base
    assert "postgres:" in overlay
    assert "postgres-bootstrap:" in overlay
    assert "PostgresAssetFindingRepository" in overlay
    assert "BSA_ASSET_REPOSITORY_BACKEND: postgres" in overlay
    assert "BSA_DATABASE_URL:" in overlay
    assert "condition: service_healthy" in overlay
    assert "condition: service_completed_successfully" in overlay
    assert "bsa_database:" in overlay
    assert "internal: true" in overlay
    assert "bsa_postgres:" in overlay
    assert "BSA_POSTGRES_PASSWORD:?set BSA_POSTGRES_PASSWORD" in overlay
