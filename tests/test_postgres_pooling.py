from app.repositories import postgres_pool,runtime_postgres_assets_findings
from app.repositories.postgres_assets_findings import PostgresAssetFindingRepository
from app.repositories.runtime_postgres_assets_findings import RuntimePostgresAssetFindingRepository


class _FakePool:
    def __init__(self,**kwargs):
        self.kwargs=kwargs
        self.closed=False

    def connection(self):
        return object()

    def close(self):
        self.closed=True


def test_postgres_pool_is_reused_per_dsn(monkeypatch):
    created=[]
    postgres_pool._POOLS.clear()
    monkeypatch.setattr(
        postgres_pool,
        "ConnectionPool",
        lambda **kwargs: created.append(_FakePool(**kwargs)) or created[-1],
    )
    monkeypatch.setenv("BSA_POSTGRES_POOL_MIN","1")
    monkeypatch.setenv("BSA_POSTGRES_POOL_MAX","5")

    first=postgres_pool.postgres_pool("postgresql://example/bsa")
    second=postgres_pool.postgres_pool("postgresql://example/bsa")

    assert first is second
    assert len(created)==1
    assert created[0].kwargs["min_size"]==1
    assert created[0].kwargs["max_size"]==5
    postgres_pool.close_postgres_pools()
    assert created[0].closed is True


class _Cursor:
    def __init__(self,calls): self.calls=calls
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def execute(self,sql,params=None): self.calls.append(str(sql))


class _Connection:
    def __init__(self,calls): self.calls=calls
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def cursor(self): return _Cursor(self.calls)


def test_default_runtime_schema_check_happens_once_per_dsn(monkeypatch):
    calls=[]
    dsn="postgresql://example/schema-once"
    runtime_postgres_assets_findings._VALIDATED_DSNS.discard(dsn)
    monkeypatch.setattr(
        PostgresAssetFindingRepository,
        "_default_connect",
        staticmethod(lambda current_dsn:_Connection(calls)),
    )

    RuntimePostgresAssetFindingRepository(dsn)
    RuntimePostgresAssetFindingRepository(dsn)

    assert calls==[
        "SELECT 1 FROM assets LIMIT 1",
        "SELECT 1 FROM findings LIMIT 1",
    ]
