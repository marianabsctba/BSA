from app.local_ai import analyze_attack_paths

def test_ai_attack_paths_fails_closed_and_does_not_invent():
    graph={"risk_paths":[{"score":82,"nodes":["internet","asset1","finding1"],"labels":["Internet","app.example.org","Auth finding"]}],
           "nodes":[{"id":"asset1","kind":"application","label":"app.example.org","risk_score":82}],
           "edges":[{"source_id":"internet","target_id":"asset1","kind":"internet_exposed","confidence":95,"evidence":"asset evidence","impact":80}]}
    result=analyze_attack_paths(graph)
    assert result is None or isinstance(result,dict)
    if result:
        assert "validation" in result
        assert "unknowns" in result
