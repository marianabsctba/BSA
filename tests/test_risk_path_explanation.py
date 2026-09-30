from app.graph import build_risk_graph
from app.correlation import correlate_evidence

def test_risk_path_contains_explanation():
    evidence = [
        {'source':'http','subject':'https://api.example.org','kind':'http_status','value':'200','confidence':98},
        {'source':'dns','subject':'api.example.org','kind':'a','value':'203.0.113.10','confidence':96},
    ]
    assets = correlate_evidence('example.org', evidence)
    graph = build_risk_graph('example.org', assets, evidence)
    assert graph['top_risk_paths']
    path = graph['top_risk_paths'][0]
    assert 'explanation' in path
    assert path['explanation']['evidence']
    assert path['explanation']['weakest_link']['confidence'] >= 0