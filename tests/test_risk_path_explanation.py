from app.graph import build_risk_graph
from app.correlation import correlate_evidence
from app.models import Asset, AssetType, Finding, Severity


def test_risk_path_contains_explanation():
    evidence = [
        {"source": "http", "subject": "https://api.example.org", "kind": "http_status", "value": "200", "confidence": 98},
        {"source": "dns", "subject": "api.example.org", "kind": "a", "value": "203.0.113.10", "confidence": 96},
    ]
    source_asset = Asset(
        id="a1",
        value="api.example.org",
        type=AssetType.APPLICATION,
        confidence=95,
        criticality=5,
        tags=["internet-facing"],
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-01T00:00:00Z",
    )
    finding = Finding(
        id="f1",
        asset_id="a1",
        title="critical exposure",
        severity=Severity.CRITICAL,
        confidence=95,
        evidence="verified",
    )
    assets = correlate_evidence("example.org", evidence)
    graph = build_risk_graph("example.org", assets, evidence, [source_asset], [finding])
    assert graph["top_risk_paths"]
    path = graph["top_risk_paths"][0]
    assert "explanation" in path
    assert path["explanation"]["evidence"]
    assert path["explanation"]["weakest_link"]["confidence"] >= 0
