from __future__ import annotations

from .postgres_assets_findings import PostgresAssetFindingRepository


class RuntimePostgresAssetFindingRepository(PostgresAssetFindingRepository):
    """PostgreSQL runtime adapter with no schema-changing side effects.

    Schema creation is reserved for explicit bootstrap/migration flows. Runtime
    API/worker processes fail closed when the expected tables are unavailable.
    """

    def __init__(self, dsn: str, connect=None):
        super().__init__(dsn, connect=connect)
        self._assert_schema_ready()

    def _ensure_schema(self) -> None:
        # Intentionally disabled for normal API/worker startup.
        return None

    def _assert_schema_ready(self) -> None:
        try:
            with self._connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM assets LIMIT 1")
                    cur.execute("SELECT 1 FROM findings LIMIT 1")
        except Exception as exc:
            raise RuntimeError(
                "PostgreSQL asset schema is not ready; run the explicit "
                "bootstrap/migration step before starting API or worker"
            ) from exc
