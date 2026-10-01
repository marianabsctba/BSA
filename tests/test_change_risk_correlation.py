def test_change_risk_correlation_combines_generic_and_technical_context():
    from app.change_risk_correlation import correlate_change_with_risk
    from app.technical_change_intelligence import TechnicalChange
    e=TechnicalChange("api.example.org","added",None,"api.example.org",("e1",),95,"warning","endpoint")
    out=correlate_change_with_risk([e],{"internet_exposed":True,"critical":True})
    assert len(out)==1
    assert out[0].asset_key=="api.example.org"
    assert out[0].technical_category=="endpoint"
    assert out[0].risk_delta>0
    assert "novo endpoint" in out[0].drivers

def test_change_risk_aggregates_per_asset():
    from app.change_risk_correlation import ChangeCorrelation, aggregate_asset_change_risk
    rows=[
        ChangeCorrelation("1","a","dns",10,20,("e1",),()),
        ChangeCorrelation("2","a","service",30,40,("e2",),()),
        ChangeCorrelation("3","b","tls",5,-10,("e3",),()),
    ]
    assert aggregate_asset_change_risk(rows)=={"a":60,"b":-10}
