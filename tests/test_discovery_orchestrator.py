def test_collector_planner_maps_pivots_to_capable_collectors():
    from app.discovery_orchestrator import CollectorPlan, plan_collectors
    from app.deep_discovery import DiscoveryPivot
    pivots=[
        DiscoveryPivot("domain","example.org","seed",95,"seed:1"),
        DiscoveryPivot("ip","203.0.113.10","dns",90,"dns:1"),
    ]
    plans=plan_collectors(pivots,enabled={"dns","certificate-transparency","ip_intel","http"})
    keys={(p.collector,p.target_kind,p.target) for p in plans}
    assert ("dns","domain","example.org") in keys
    assert ("certificate-transparency","domain","example.org") in keys
    assert ("ip_intel","ip","203.0.113.10") in keys
    assert ("http","ip","203.0.113.10") not in keys

def test_collector_planner_deduplicates_and_bounds_jobs():
    from app.discovery_orchestrator import plan_collectors
    from app.deep_discovery import DiscoveryPivot
    pivots=[DiscoveryPivot("domain","example.org","seed",90,"e1")]*20
    plans=plan_collectors(pivots,max_jobs=2)
    assert len(plans)==2
    assert len({(p.collector,p.target_kind,p.target) for p in plans})==2
