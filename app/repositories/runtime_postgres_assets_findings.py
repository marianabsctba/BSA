from __future__ import annotations

import threading

from .postgres_assets_findings import PostgresAssetFindingRepository


_VALIDATED_DSNS: set[str]=set()
_SCHEMA_LOCK=threading.Lock()


class RuntimePostgresAssetFindingRepository(PostgresAssetFindingRepository):
    """Runtime PostgreSQL adapter that never performs schema DDL.

    Bootstrap/migration owns DDL. Normal API/worker instances only verify that
    the expected tables are present. With the default pooled connection this
    verification is performed once per DSN/process; injected test connections
    remain independently verifiable.
    """

    def __init__(self, dsn: str, connect=None):
        self._injected_connect=connect is not None
        super().__init__(dsn,connect=connect)
        self._assert_schema_ready()

    def _ensure_schema(self) -> None:
        return None

    def _assert_schema_ready(self) -> None:
        if self._injected_connect:
            self._verify_schema()
            return
        with _SCHEMA_LOCK:
            if self._dsn in _VALIDATED_DSNS:
                return
            self._verify_schema()
            _VALIDATED_DSNS.add(self._dsn)

    def _verify_schema(self) -> None:
        try:
            with self._connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM assets LIMIT 1")
                    cur.execute("SELECT 1 FROM findings LIMIT 1")
        except Exception as exc:
            raise RuntimeError(
                "PostgreSQL asset schema is not ready; run postgres-bootstrap first"
            ) from exc
