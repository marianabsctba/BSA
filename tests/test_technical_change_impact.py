def test_service_change_has_distinct_impact():
    from app.technical_change_intelligence import TechnicalChange, technical_change_impact
    e=TechnicalChange("443","added",None,"443",("e1",),95,"warning","service")
    out=technical_change_impact(e,{"internet_exposed":True})
    assert out["category"]=="service"
    assert out["impact"]==60
    assert "novo serviço/porta" in out["drivers"]

def test_certificate_change_does_not_equal_port_exposure():
    from app.technical_change_intelligence import TechnicalChange, technical_change_impact
    e=TechnicalChange("cert","evidence_changed","old","new",("old","new"),95,"info","tls")
    out=technical_change_impact(e,{"internet_exposed":True})
    assert out["impact"]==5
    assert "evidência TLS alterada" in out["drivers"]
