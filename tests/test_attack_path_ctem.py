def test_ctem_attack_path_context_requires_real_paths():
    from app.risk_engine import apply_attack_path_context
    base={"priority":60,"drivers":[]}
    assert apply_attack_path_context(base,[])==base

def test_ctem_attack_path_context_adds_evidence_driver():
    from app.risk_engine import apply_attack_path_context
    from app.attack_paths import AttackEdge, AttackPath
    edge=AttackEdge("a","b","exposes",80,("ev-1",))
    p=AttackPath(("a","b"),(edge,),80,75,("evidence",))
    out=apply_attack_path_context({"priority":60,"drivers":[]},[p])
    assert out["attack_path_score"]==80
    assert out["attack_path_confidence"]==75
    assert "caminho de exposição sustentado por evidências" in out["drivers"]
    assert out["priority"] > 60
