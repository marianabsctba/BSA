from app.discovery import adaptive_discovery

def test_adaptive_discovery_is_bounded_and_supported_checks_only():
    out=adaptive_discovery("example.org",max_rounds=3,max_assets=10)
    assert out["max_rounds"]==3
    assert len(out["rounds"])<=3
    allowed={"dns","http","tls","ct","ports","rdap","ip_intel"}
    for r in out["rounds"]:
        assert set(r["checks"]).issubset(allowed)


def test_adaptive_discovery_exposes_bounded_evidence_backed_candidates(monkeypatch):
    from app import discovery

    monkeypatch.setattr(discovery, "collect_target", lambda target, checks: {
        "target": target,
        "evidence": [
            {"source": "ct", "kind": "certificate_name", "value": "api.example.org", "confidence": 92},
            {"source": "ct", "kind": "certificate_name", "value": "admin.external.example.net", "confidence": 99},
        ],
        "evidence_count": 2,
        "confidence": 95,
    })
    monkeypatch.setattr(discovery, "prioritize_collection", lambda *args: {"priorities": []})
    out=discovery.adaptive_discovery("example.org", max_rounds=3, max_assets=1)
    assert [x["value"] for x in out["candidates"]] == ["api.example.org"]
    assert out["candidates"][0]["evidence_refs"]
    assert out["candidates"][0]["confidence"] >= 92


def test_candidate_collection_plan_is_bounded_and_cache_aware():
    from app.discovery_orchestrator import plan_candidate_collection, CollectionCacheEntry
    from datetime import datetime, timezone

    now=datetime.now(timezone.utc)
    cache=[CollectionCacheEntry("http","hostname","api.example.org",now,3600,"fp")]
    plans=plan_candidate_collection(
        [{"kind":"hostname","value":"api.example.org","confidence":95},
         {"kind":"hostname","value":"admin.example.org","confidence":80}],
        enabled={"http","tls"},
        max_jobs=3,
        cache=cache,
        now=now,
    )
    assert plans
    assert all(p.target == "admin.example.org" for p in plans)
    assert len(plans) <= 3
