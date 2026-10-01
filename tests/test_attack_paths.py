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
