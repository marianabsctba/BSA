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

def test_risk_path_includes_business_impact():
    asset = Asset(id='a2', value='impact.example.org', type=AssetType.APPLICATION, confidence=95, criticality=5, tags=['internet-facing'], first_seen='2026-01-01T00:00:00Z', last_seen='2026-01-01T00:00:00Z')
    finding = Finding(id='f2', asset_id='a2', title='critical exposure', severity=Severity.CRITICAL, confidence=95, evidence='test')
    graph = build_risk_graph('example.org', [asset], [], [asset], [finding])
    assert graph['risk_summary']['business_impact'] >= 100
    assert any(x['explanation']['evidence'] for x in graph['top_risk_paths'])


def test_remediation_options_rank_paths():
    asset = Asset(id='a3', value='planner.example.org', type=AssetType.APPLICATION, confidence=95, criticality=5, tags=['internet-facing'], first_seen='2026-01-01T00:00:00Z', last_seen='2026-01-01T00:00:00Z')
    finding = Finding(id='f3', asset_id='a3', title='critical exposure', severity=Severity.CRITICAL, confidence=95, evidence='test')
    graph = build_risk_graph('example.org', [asset], [], [asset], [finding])
    assert 'top_risk_paths' in graph
