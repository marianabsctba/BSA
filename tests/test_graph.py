from app.graph import build_attack_surface_graph
from app.correlation import correlate_evidence

def test_dynamic_graph_contains_evidence_backed_nodes_and_edges():
    evidence = [
        {'source':'dns','subject':'api.example.org','kind':'a','value':'203.0.113.10','confidence':96},
        {'source':'certificate-transparency','subject':'example.org','kind':'certificate_name','value':'api.example.org','confidence':88},
        {'source':'http','subject':'https://api.example.org','kind':'http_status','value':'200','confidence':98},
    ]
    assets = correlate_evidence('example.org', evidence)
    graph = build_attack_surface_graph('example.org', assets, evidence)
    labels = {n['label'] for n in graph['nodes']}
    kinds = {e['kind'] for e in graph['edges']}
    assert 'example.org' in labels
    assert 'api.example.org' in labels
    assert '203.0.113.10' in labels
    assert 'resolves_to' in kinds
    assert 'certificate_observed' in kinds