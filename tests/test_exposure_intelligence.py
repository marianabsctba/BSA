from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def auth():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    return {}

def test_exposure_reduction_and_attack_paths():
    h=auth()
    r=client.get("/api/v1/exposure/reduction",headers=h)
    assert r.status_code==200
    assert "aggregate_exposure" in r.json()
    r=client.get("/api/v1/attack-paths",headers=h)
    assert r.status_code==200
    assert "paths" in r.json()
    assert "summary" in r.json()


def test_asset_dna_and_radar():
    h=auth()
    r=client.get("/api/v1/assets/ast-002/dna",headers=h)
    assert r.status_code==200
    assert r.json()["fingerprint"]
    r=client.get("/api/v1/radar",headers=h)
    assert r.status_code==200
    assert any(x["asset_id"]=="ast-002" for x in r.json()["assets"])


def test_ctem_queue_and_business_impact():
    h=auth()
    r=client.get("/api/v1/exposure/ctem",headers=h)
    assert r.status_code==200
    assert "items" in r.json()
    r=client.get("/api/v1/exposure/business-impact",headers=h)
    assert r.status_code==200
    assert "items" in r.json()


def test_tenant_scoped_live_graph():
    h=auth()
    r=client.get("/api/v1/graph",headers=h)
    assert r.status_code==200
    data=r.json()
    assert "nodes" in data and "edges" in data and "top_risk_paths" in data


def test_graph_contains_exposure_and_finding_relationships():
    h=auth()
    data=client.get("/api/v1/graph",headers=h).json()
    assert any(n["kind"]=="internet" for n in data["nodes"])
    assert any(n["kind"]=="finding" for n in data["nodes"])


def test_ctem_plan_endpoint():
    h=auth()
    data=client.get("/api/v1/exposure/ctem",headers=h).json()
    item=(data.get("items") or [None])[0]
    payload={"asset_ids":[item["asset_id"]],"finding_ids":[]} if item else {"asset_ids":[],"finding_ids":[]}
    r=client.post("/api/v1/exposure/ctem/plan",headers={**h,"Content-Type":"application/json"},json=payload)
    assert r.status_code==200
    assert "items" in r.json()


def test_ctem_plan_persists_and_lifecycle():
    h=auth()
    data=client.get("/api/v1/exposure/ctem",headers=h).json()
    item=(data.get("items") or [None])[0]
    if not item:
        return
    payload={"asset_ids":[item["asset_id"]],"finding_ids":[]}
    created=client.post("/api/v1/exposure/ctem/plan",headers={**h,"Content-Type":"application/json"},json=payload).json()["items"]
    assert created
    plan_id=created[0]["plan_id"]
    listed=client.get("/api/v1/exposure/ctem/plans",headers=h).json()["items"]
    assert any(x["plan_id"]==plan_id for x in listed)
    updated=client.patch(f"/api/v1/exposure/ctem/plans/{plan_id}",headers={**h,"Content-Type":"application/json"},json={"status":"approved"})
    assert updated.status_code==200
    assert updated.json()["status"]=="approved"


def test_ctem_plans_are_durable_and_tenant_scoped():
    h=auth()
    data=client.get("/api/v1/exposure/ctem",headers=h).json()
    item=(data.get("items") or [None])[0]
    if not item:
        return
    created=client.post("/api/v1/exposure/ctem/plan",headers={**h,"Content-Type":"application/json"},json={"asset_ids":[item["asset_id"]],"finding_ids":[]}).json()["items"]
    assert created
    plans=client.get("/api/v1/exposure/ctem/plans",headers=h).json()["items"]
    assert any(x["plan_id"]==created[0]["plan_id"] for x in plans)
    assert all(x.get("plan_id") and x.get("asset_id") for x in plans)


def test_mssp_command_center_is_tenant_aggregated():
    h=auth()
    r=client.get("/api/v1/mssp/command-center",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert "tenants" in data and "summary" in data


def test_mssp_command_center_has_ctem_lifecycle_metrics():
    h=auth()
    r=client.get("/api/v1/mssp/command-center",headers=h)
    if r.status_code != 200:
        return
    data=r.json()
    for tenant in data["tenants"]:
        assert "critical_findings" in tenant
        assert "in_progress" in tenant
        assert "remediated" in tenant
        assert "ctem_aging" in tenant


def test_mssp_sla_and_residual_metrics():
    h=auth(); r=client.get("/api/v1/mssp/command-center",headers=h)
    if r.status_code != 200: return
    data=r.json(); assert "sla_compliance" in data["summary"]
    assert "risk_residual" in data["summary"] and "risk_reduction_30d" in data["summary"]
    for t in data["tenants"]:
        assert 0 <= t["sla_compliance"] <= 100
        assert "avg_ctem_age_days" in t and "risk_reduction_30d" in t


def test_mssp_trend_contract():
    h=auth()
    r=client.get("/api/v1/mssp/command-center/trend",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert data["days"]==90
        assert "tenants" in data


def test_graph_control_coverage_and_chokepoints():
    h=auth()
    r=client.get("/api/v1/graph/control-coverage",headers=h)
    assert r.status_code==200
    data=r.json()
    assert "coverage" in data and "controls" in data and "choke_points" in data
    assert 0 <= data["coverage"]["coverage_percent"] <= 100


def test_local_ai_status_and_copilot_grounding():
    h=auth()
    r=client.get("/api/v1/exposure/ai/status",headers=h)
    assert r.status_code==200
    data=r.json()
    assert data["provider"]=="ollama-local"
    r=client.get("/api/v1/exposure/copilot",headers=h,params={"question":"quais ativos estão sem owner?"})
    assert r.status_code==200
    out=r.json()
    assert "evidence" in out and "ai" in out
    assert out["ai"]["internet_required"] if "internet_required" in out["ai"] else True


def test_attack_path_local_ai_contract():
    h=auth()
    r=client.post("/api/v1/graph/attack-path/explain",headers={**h,"Content-Type":"application/json"},json={"path":[]})
    assert r.status_code==400
    r=client.get("/api/v1/graph")
    graph=r.json()
    path=(graph.get("top_risk_paths") or [None])[0]
    if path:
        r=client.post("/api/v1/graph/attack-path/explain",headers={**h,"Content-Type":"application/json"},json={"path":path["nodes"]})
        assert r.status_code==200
        assert "ai" in r.json()


def test_digital_risk_ingest_and_summary():
    h=auth()
    payload={"category":"phishing","title":"Brand impersonation","indicator":"https://evil.example","source":"test","severity":"high","confidence":92,"evidence":{"screenshot":"sha256:test"}}
    r=client.post("/api/v1/digital-risk/events",headers={**h,"Content-Type":"application/json"},json=payload)
    assert r.status_code==200
    event=r.json()
    r=client.get("/api/v1/digital-risk",headers=h)
    assert r.status_code==200
    summary=r.json()["summary"]
    assert summary["total"]>=1
    assert summary["high_risk_open"]>=1
    assert "takedown_candidates" not in summary
    assert r.json()["status"]=="queued"


def test_brand_impersonation_evidence_endpoint():
    h=auth()
    payload={"indicator":"https://evil.example/be-safe-login","brand":"Be Safe","title":"Be Safe Login","html_excerpt":"Be Safe Secure Login","visual_similarity":88,"text_similarity":82}
    r=client.post("/api/v1/digital-risk/brand/analyze",headers={**h,"Content-Type":"application/json"},json=payload)
    assert r.status_code==200
    out=r.json()
    assert out["verdict"]=="likely_impersonation"
    assert out["score"]>=70
    assert "evidence" in out


def test_infrastructure_correlation_endpoint():
    h=auth()
    payload={"indicator":"login.example.test","indicator_type":"domain","ip":"203.0.113.10","asn":"AS64500","certificate_sha256":"cert123","favicon_sha256":"fav123","related_domains":["secure.example.test"],"confidence":90}
    r=client.post("/api/v1/digital-risk/infrastructure/analyze",headers={**h,"Content-Type":"application/json"},json=payload)
    assert r.status_code==200
    out=r.json()
    assert out["link_count"]>=4
    assert "cluster_strength" in out


def test_discovery_infrastructure_contract():
    h=auth()
    r=client.post("/api/v1/discovery/example.com/infrastructure",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert "discovery" in data and "links" in data and "cluster_strength" in data


def test_infrastructure_graph_contract():
    h=auth()
    r=client.post("/api/v1/discovery/example.com/infrastructure/graph",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert "nodes" in data and "edges" in data and "summary" in data
        for e in data["edges"]:
            assert 0 <= e["confidence"] <= 100


def test_easm_overview_contract():
    h=auth()
    r=client.get("/api/v1/easm/overview",headers=h)
    assert r.status_code==200
    data=r.json()
    assert "summary" in data and "inventory" in data and "changes" in data and "risk" in data
    assert data["summary"]["total_assets"]>=0
    assert 0 <= data["changes"]["low_confidence"] <= data["summary"]["total_assets"]


def test_bounded_easm_discovery_contract():
    h=auth()
    r=client.post("/api/v1/easm/discover/example.com?max_depth=0&max_assets=5",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert data["summary"]["discovered_targets"]<=5
        assert data["summary"]["max_depth_reached"]<=0
        assert "nodes" in data and "edges" in data and "assets" in data

def test_easm_discovery_rejects_unbounded_parameters():
    h=auth()
    assert client.post("/api/v1/easm/discover/example.com?max_depth=4",headers=h).status_code==400
    assert client.post("/api/v1/easm/discover/example.com?max_assets=101",headers=h).status_code==400


def test_easm_lifecycle_contract():
    h=auth()
    r=client.post("/api/v1/easm/lifecycle/example.com",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert "summary" in data and "assets" in data
        assert data["summary"]["new"] + data["summary"]["changed"] + data["summary"]["stable"] == data["summary"]["assets"]


def test_risk_overview_contract():
    h=auth()
    r=client.get("/api/v1/risk/overview",headers=h)
    assert r.status_code==200
    data=r.json()
    assert "summary" in data and "items" in data
    for item in data["items"]:
        risk=item["risk"]
        assert 0 <= risk["score"] <= 100
        assert 0 <= risk["likelihood"] <= 100
        assert 0 <= risk["impact"] <= 100
        assert 0 <= risk["exposure"] <= 100

def test_cpe_normalization_is_conservative():
    h=auth()
    r=client.get("/api/v1/risk/overview",headers=h)
    assert r.status_code==200
    for item in r.json()["items"]:
        if item["cpe"]:
            assert item["cpe"].startswith("cpe:2.3:") or item["cpe"].startswith("cpe:/")


def test_cve_correlation_requires_confirmed_version():
    from app.cve_correlation import CVERange, match_cve
    candidates=[CVERange("CVE-TEST","vendor","nginx","1.2.0","1.2.9",source="test")]
    potential=match_cve("nginx",None,"cpe:2.3:a:vendor:nginx:*:*:*:*:*:*:*:*",candidates)
    assert potential[0].state=="potential"
    confirmed=match_cve("nginx","1.2.5","cpe:2.3:a:vendor:nginx:1.2.5:*:*:*:*:*:*:*",candidates)
    assert confirmed[0].state=="confirmed_affected"
    safe=match_cve("nginx","1.3.0",None,candidates)
    assert safe[0].state=="not_affected"


def test_policy_aware_risk_has_inherent_and_residual_scores():
    h=auth()
    response=client.get("/api/v1/risk/register",headers=h)
    assert response.status_code==200
    data=response.json()
    assert "policy" in data and "summary" in data and "items" in data
    for item in data["items"]:
        risk=item["risk"]
        assert 0<=risk["inherent_score"]<=100
        assert 0<=risk["residual_score"]<=100
        assert 0<=risk["uncertainty"]<=100


def test_risk_attack_paths_contract():
    h=auth()
    response=client.get("/api/v1/risk/attack-paths",headers=h)
    assert response.status_code==200
    data=response.json()
    assert "summary" in data and "paths" in data
    for path in data["paths"]:
        assert 0<=path["score"]<=100
        assert "decision_factors" in path


def test_risk_remediation_options_contract():
    h=auth()
    response=client.get("/api/v1/risk/remediation-options",headers=h)
    assert response.status_code==200
    data=response.json()
    assert "summary" in data and "options" in data
    for item in data["options"]:
        assert 0<=item["before"]<=100
        assert 0<=item["after"]<=100
        assert 0<=item["reduction_percent"]<=100


def test_tenant_risk_policy_validation_contract():
    h=auth()
    response=client.get("/api/v1/risk/policy",headers=h)
    assert response.status_code==200
    data=response.json()
    assert data["policy"]["tenant_id"]
    assert data["validation"]==[]
    bad={"likelihood_weight":0.9,"impact_weight":0.9,"confidence_weight":0.1}
    response=client.put("/api/v1/risk/policy",headers={**h,"Content-Type":"application/json"},json=bad)
    assert response.status_code==400


def test_risk_policy_studio_api_read_is_tenant_scoped():
    h=auth()
    response=client.get("/api/v1/risk/policy",headers=h)
    assert response.status_code==200
    data=response.json()
    assert data["policy"]["tenant_id"]
