from app.changes import seed_changes
from app.models import Asset, AssetType


def test_change_engine_emits_tagged_changes():
    assets = [Asset(
        id="a1", value="vpn.example.org", type=AssetType.SUBDOMAIN,
        confidence=90, criticality=5, source="dns",
        tags=["new", "changed"], first_seen="now", last_seen="now"
    )]
    changes = seed_changes(assets)
    assert len(changes) == 2
    assert {c.kind for c in changes} == {"new_asset", "service_change"}
