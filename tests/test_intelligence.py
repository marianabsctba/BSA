from app.intelligence import blast_radius, ownership_confidence
from app.models import Asset, AssetType


def make_asset(**kwargs):
    base = dict(
        id="a1", value="example.org", type=AssetType.DOMAIN,
        confidence=80, criticality=4, source="dns",
        tags=["internet-facing"], first_seen="now", last_seen="now",
    )
    base.update(kwargs)
    return Asset(**base)


def test_confirmed_owner_tag_forces_confirmation():
    result = ownership_confidence(make_asset(tags=["confirmed-owner"]))
    assert result.score == 100
    assert result.state == "confirmed"


def test_third_party_reduces_ownership_confidence():
    result = ownership_confidence(make_asset(tags=["third-party"]))
    assert result.score == 55
    assert result.state == "candidate"


def test_blast_radius_respects_context():
    score = blast_radius(make_asset(criticality=5, tags=["internet-facing", "remote-access", "production"]))
    assert score == 100
