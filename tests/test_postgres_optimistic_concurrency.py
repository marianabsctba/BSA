from datetime import datetime,timezone

import pytest

from app.models import Asset,AssetType
from app.repositories.postgres_assets_findings import (
    ConcurrentUpdateError,
    PostgresAssetFindingRepository,
)


def _asset_payload():
    now=datetime.now(timezone.utc).isoformat()
    return Asset(
        tenant_id="tenant-a",
        id="asset-a",
        value="a.example.org",
        type=AssetType.DOMAIN,
        first_seen=now,
        last_seen=now,
    ).model_dump(mode="json")


class _State:
    def __init__(self, *, conflict=False):
        self.calls=[]
        self.conflict=conflict
        self.rows=[(_asset_payload(),"version-1")]


class _Cursor:
    def __init__(self,state):
        self.state=state
        self.rowcount=0

    def __enter__(self): return self
    def __exit__(self,*args): return False

    def execute(self,sql,params=None):
        normalized=" ".join(str(sql).split())
        self.state.calls.append((normalized,params))
        if normalized.startswith("UPDATE assets"):
            self.rowcount=0 if self.state.conflict else 1

    def fetchall(self):
        return list(self.state.rows)


class _Connection:
    def __init__(self,state): self.state=state
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def cursor(self): return _Cursor(self.state)


class _Repository(PostgresAssetFindingRepository):
    def _ensure_schema(self): return None


def _repository(state):
    return _Repository(
        "postgresql://example/bsa",
        connect=lambda dsn:_Connection(state),
    )


def test_read_only_tracked_asset_is_not_written_back():
    state=_State()
    repository=_repository(state)

    assert len(repository.list_assets("tenant-a"))==1
    repository.persist()

    assert not any(sql.startswith("UPDATE assets") for sql,_ in state.calls)
    assert not any(sql.startswith("INSERT INTO assets") for sql,_ in state.calls)


def test_modified_tracked_asset_uses_read_version_for_compare_and_swap():
    state=_State()
    repository=_repository(state)
    asset=repository.list_assets("tenant-a")[0]
    asset.owner="security-team"

    repository.persist()

    updates=[call for call in state.calls if call[0].startswith("UPDATE assets")]
    assert len(updates)==1
    sql,params=updates[0]
    assert "updated_at=%s" in sql
    assert params[-1]=="version-1"


def test_stale_tracked_asset_fails_closed_instead_of_overwriting():
    state=_State(conflict=True)
    repository=_repository(state)
    asset=repository.list_assets("tenant-a")[0]
    asset.owner="security-team"

    with pytest.raises(ConcurrentUpdateError,match="changed concurrently"):
        repository.persist()
