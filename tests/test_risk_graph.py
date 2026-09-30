from app.graph import build_risk_graph
from app.correlation import correlate_evidence
from app.models import Asset, AssetType, Finding, Severity

def test_risk_graph_scores_contextual_asset():
    asset = Asset(id='a1', value='api.example.org', type=AssetType.APPLICATION, confidence=95, criticality=5, tags=['internet-facing'], first_seen='2026-01-01T00:00:00Z', last_seen='2026-01-01T00:00:00Z')
    finding = Finding(id='f1', asset_id='a1', title='critical exposure', severity=Severity.CRITICAL, confidence=95, evidence='test')
    evidence = [{'source':'http','subject':'https://api.example.org','kind':'http_status','value':'200','confidence':98}]
    assets = correlate_evidence('example.org', evidence)
    graph = build_risk_graph('example.org', assets, evidence, [asset], [finding])
    node = next(n for n in graph['nodes'] if n['label'] == 'api.example.org')
    assert node['risk_score'] >= 85
    assert node['risk_band'] == 'critical'
    assert graph['risk_summary']['critical'] == 1