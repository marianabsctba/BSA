def test_attack_path_requires_evidence_and_never_self_loops():
    from app.attack_paths import AttackEdge, build_evidence_graph
    edges=[
        AttackEdge("a","b","exposes",90,("ev-1",)),
        AttackEdge("b","c","depends-on",80,("ev-2",)),
        AttackEdge("c","d","bad",80,()),
        AttackEdge("d","d","loop",100,("ev-3",)),
    ]
    g=build_evidence_graph(edges)
    assert "a" in g and "b" in g
    assert "c" not in g
    assert "d" not in g

def test_attack_path_score_is_evidence_based():
    from app.attack_paths import AttackEdge, find_paths
    edges=[
        AttackEdge("internet","app","resolves-to",95,("dns-1",)),
        AttackEdge("app","service","routes-to",85,("http-1",)),
        AttackEdge("service","identity","reaches",70,("rel-1",)),
    ]
    paths=find_paths(edges,"internet",{"identity"})
    assert len(paths)==1
    assert paths[0].nodes==("internet","app","service","identity")
    assert paths[0].confidence==70
    assert paths[0].score==83


def test_paths_from_risk_graph_uses_only_evidence_backed_edges():
    from app.attack_paths import paths_from_risk_graph
    graph={
        "nodes":[
            {"id":"internet","kind":"internet","label":"Internet"},
            {"id":"app","kind":"application","label":"app"},
            {"id":"finding","kind":"finding","label":"CVE"},
        ],
        "edges":[
            {"source_id":"internet","target_id":"app","kind":"internet_exposed","confidence":95,
             "evidence_refs":["asset:e1"]},
            {"source_id":"app","target_id":"finding","kind":"finding_observed","confidence":90,
             "evidence_refs":["finding:e1"]},
            {"source_id":"internet","target_id":"finding","kind":"invented","confidence":99,
             "evidence_refs":[]},
        ],
    }
    paths=paths_from_risk_graph(graph)
    assert len(paths)==1
    assert paths[0].confidence==90
    assert all(edge.evidence_refs for edge in paths[0].edges)
