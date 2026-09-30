from app.graph import build_risk_graph
from app.correlation import correlate_evidence
from app.models import Asset, AssetType, Finding, Severity


def test_risk_graph_exposes_top_risk_path():
    asset = Asset(
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
        evidence="test",
    )
    evidence = [
        {"source": "http", "subject": "https://api.example.org", "kind": "http_status", "value": "200", "confidence": 98},
        {"source": "dns", "subject": "api.example.org", "kind": "a", "value": "203.0.113.10", "confidence": 96},
    ]
    assets = correlate_evidence("example.org", evidence)
    graph = build_risk_graph("example.org", assets, evidence, [asset], [finding])
    assert graph["risk_summary"]["risk_paths"] >= 1
    assert graph["top_risk_paths"][0]["score"] >= 70
    assert "api.example.org" in graph["top_risk_paths"][0]["labels"]
