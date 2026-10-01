from app.discovery import adaptive_discovery

def test_adaptive_discovery_is_bounded_and_supported_checks_only():
    out=adaptive_discovery("example.org",max_rounds=3,max_assets=10)
    assert out["max_rounds"]==3
    assert len(out["rounds"])<=3
    allowed={"dns","http","tls","ct","ports","rdap","ip_intel"}
    for r in out["rounds"]:
        assert set(r["checks"]).issubset(allowed)
