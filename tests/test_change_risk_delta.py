def test_change_risk_delta_for_new_internet_exposure():
    from app.change_intelligence import ChangeEvent, change_risk_delta
    e=ChangeEvent("new.example.org","added",None,"new.example.org",("e1",),95,"warning",{"kind":"hostname"})
    out=change_risk_delta(e,{"internet_exposed":True,"critical":True})
    assert out["delta"]==40
    assert "novo ativo exposto à Internet" in out["drivers"]
    assert "ativo crítico" in out["drivers"]

def test_change_risk_delta_does_not_invent_delta_without_significant_evidence_change():
    from app.change_intelligence import ChangeEvent, change_risk_delta
    e=ChangeEvent("a","evidence_changed","e1","e2",("e1","e2"),95,"info",{"confidence_delta":5})
    assert change_risk_delta(e)["delta"]==0
