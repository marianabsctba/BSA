from datetime import datetime, timedelta, timezone

def test_planner_skips_fresh_collection_cache():
    from app.discovery_orchestrator import CollectionCacheEntry, plan_collectors
    from app.deep_discovery import DiscoveryPivot
    now=datetime(2026,10,1,tzinfo=timezone.utc)
    cache=[CollectionCacheEntry("dns","domain","example.org",now-timedelta(minutes=10),3600,"fp")]
    pivots=[DiscoveryPivot("domain","example.org","seed",95,"seed")]
    plans=plan_collectors(pivots,enabled={"dns","http"},cache=cache,now=now)
    assert ("dns","domain","example.org") not in {(p.collector,p.target_kind,p.target) for p in plans}
    assert ("http","domain","example.org") in {(p.collector,p.target_kind,p.target) for p in plans}

def test_expired_cache_does_not_suppress_collection():
    from app.discovery_orchestrator import CollectionCacheEntry, plan_collectors
    from app.deep_discovery import DiscoveryPivot
    now=datetime(2026,10,1,tzinfo=timezone.utc)
    cache=[CollectionCacheEntry("dns","domain","example.org",now-timedelta(hours=2),3600,"fp")]
    pivots=[DiscoveryPivot("domain","example.org","seed",95,"seed")]
    plans=plan_collectors(pivots,enabled={"dns"},cache=cache,now=now)
    assert len(plans)==1
