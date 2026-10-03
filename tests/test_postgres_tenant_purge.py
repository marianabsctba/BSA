from app.repositories.postgres_assets_findings import PostgresAssetFindingRepository


class _Cursor:
    def __init__(self,calls):
        self.calls=calls
        self.rowcount=0

    def __enter__(self): return self
    def __exit__(self,*args): return False

    def execute(self,sql,params=None):
        normalized=" ".join(str(sql).split())
        self.calls.append((normalized,params))
        if normalized.startswith("DELETE FROM findings"):
            self.rowcount=2
        elif normalized.startswith("DELETE FROM assets"):
            self.rowcount=1


class _Connection:
    def __init__(self,calls): self.calls=calls
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def cursor(self): return _Cursor(self.calls)


class _Repository(PostgresAssetFindingRepository):
    def _ensure_schema(self):
        return None


def test_postgres_purge_deletes_only_requested_tenant_and_children_first():
    calls=[]
    repository=_Repository(
        "postgresql://example/bsa",
        connect=lambda dsn:_Connection(calls),
    )

    deleted=repository.purge_tenant("tenant-a")

    assert deleted=={"assets":1,"findings":2}
    delete_calls=[call for call in calls if call[0].startswith("DELETE FROM")]
    assert delete_calls==[
        ("DELETE FROM findings WHERE tenant_id=%s",("tenant-a",)),
        ("DELETE FROM assets WHERE tenant_id=%s",("tenant-a",)),
    ]
