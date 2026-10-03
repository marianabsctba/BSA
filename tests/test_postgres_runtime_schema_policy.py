import pytest

from app.repositories.runtime_postgres_assets_findings import RuntimePostgresAssetFindingRepository


class _Cursor:
    def __init__(self, calls, fail=False):
        self.calls=calls
        self.fail=fail

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append(str(sql))
        if self.fail:
            raise RuntimeError("missing schema")


class _Connection:
    def __init__(self, calls, fail=False):
        self.calls=calls
        self.fail=fail

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return _Cursor(self.calls, self.fail)


def test_runtime_postgres_adapter_never_creates_schema():
    calls=[]

    RuntimePostgresAssetFindingRepository(
        "postgresql://example/bsa",
        connect=lambda dsn: _Connection(calls),
    )

    assert calls==[
        "SELECT 1 FROM assets LIMIT 1",
        "SELECT 1 FROM findings LIMIT 1",
    ]
    assert not any("CREATE " in sql.upper() for sql in calls)


def test_runtime_postgres_adapter_fails_closed_when_schema_missing():
    with pytest.raises(RuntimeError, match="schema is not ready"):
        RuntimePostgresAssetFindingRepository(
            "postgresql://example/bsa",
            connect=lambda dsn: _Connection([], fail=True),
        )
