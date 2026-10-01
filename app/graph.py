from dataclasses import dataclass
from hashlib import sha256
from .risk_policy import calculate_risk


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    confidence: int
    risk_score: int = 0
    risk_band: str = "unknown"


@dataclass(frozen=True)
class Relationship:
    source_id: str
    target_id: str
    kind: str
    confidence: int
    evidence: str
    impact: int = 0


def node_id(kind: str, value: str) -> str:
    return sha256(f"{kind}:{value.lower()}".encode()).hexdigest()[:16]


def risk_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _risk_for(asset, findings):
    if asset is None:
        return 0
    score = min(20, asset.criticality * 4) + round(asset.confidence * 0.10)
    if "internet-facing" in asset.tags:
        score += 18
    if "remote-access" in asset.tags:
        score += 8
    if "candidate" in asset.tags or "shadow" in asset.tags:
        score += 10
    points = {"info": 0, "low": 5, "medium": 12, "high": 22, "critical": 40}
    for finding in findings or []:
        if finding.asset_id == asset.id and finding.status == "open":
            score += points.get(finding.severity.value, 0)
    return min(100, score)


def _path_score(nodes, edges, path):
    edge_by_key = {(e.source_id, e.target_id): e for e in edges}
    confidences = []
    for left, right in zip(path, path[1:]):
        edge = edge_by_key.get((left, right))
        if edge:
            confidences.append(edge.confidence)
    node_scores = [nodes[n].risk_score for n in path if nodes[n].risk_score]
    risk = max(node_scores, default=0)
    evidence_confidence = min(confidences, default=0)
    impact = max((next((e.impact for e in edges if e.source_id==left and e.target_id==right), 0) for left,right in zip(path,path[1:])), default=0)
    return min(100, round(risk * 0.55 + evidence_confidence * 0.25 + impact * 0.20))


def _path_explanation(nodes, edges, path):
    edge_by_key = {(e.source_id, e.target_id): e for e in edges}
    evidence = []
    weakest = None
    for left, right in zip(path, path[1:]):
        edge = edge_by_key.get((left, right))
        if not edge:
            continue
        item = {"from": nodes[left].label, "to": nodes[right].label, "relationship": edge.kind, "confidence": edge.confidence, "impact": edge.impact, "source": edge.evidence}
        evidence.append(item)
        if weakest is None or edge.confidence < weakest["confidence"]:
            weakest = item
    reasons = ["cadeia de exposição alcançável pela superfície observada"]
    if any(nodes[n].risk_band == "critical" for n in path):
        reasons.append("há ativo crítico na cadeia")
    if any(nodes[n].kind == "threat" for n in path):
        reasons.append("há evidência de inteligência de ameaça associada")
    return {"reasons": reasons, "evidence": evidence, "weakest_link": weakest}


def _security_controls(asset):
    controls=[]
    for tag in getattr(asset,"tags",[]) or []:
        raw=str(tag).strip()
        if ":" not in raw: continue
        kind,value=raw.split(":",1)
        kind=kind.lower().strip(); value=value.strip()
        if kind in {"edr","xdr","waf","firewall","mfa","vpn","iam","cdn","ngfw","casb","cspm","backup"} and value:
            controls.append({"type":kind,"provider":value,"source":"asset_tag","confidence":80})
    for source in getattr(asset,"sources",[]) or []:
        s=str(source).lower()
        if any(k in s for k in ("crowdstrike","qualys","sophos","sentinel","defender")) and not any(x["type"] in {"edr","xdr"} for x in controls):
            controls.append({"type":"edr","provider":source,"source":"asset_source","confidence":55})
    return controls

def _top_risk_paths(nodes, edges, limit=10):
    adjacency = {}
    for edge in edges:
        adjacency.setdefault(edge.source_id, []).append(edge.target_id)

    paths = []

    def walk(start, current, path):
        if len(path) > 5:
            return
        neighbors = adjacency.get(current, [])
        if not neighbors:
            if len(path) >= 2:
                paths.append(path)
            return
        for nxt in neighbors:
            if nxt in path:
                continue
            walk(start, nxt, path + [nxt])

    for start in nodes:
        walk(start, start, [start])

    ranked = []
    seen = set()
    for path in paths:
        key = tuple(path)
        if key in seen:
            continue
        seen.add(key)
        score = _path_score(nodes, edges, path)
        if score >= 45:
            ranked.append({
                "score": score,
                "band": risk_band(score),
                "nodes": path,
                "labels": [nodes[n].label for n in path],
                "kinds": [nodes[n].kind for n in path],
                "explanation": _path_explanation(nodes, edges, path),
            })
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[:limit]


def build_risk_graph(target: str, assets, evidence: list[dict], source_assets=None, findings=None):
    nodes = {}
    edges = []
    source_assets = source_assets or []
    findings = findings or []
    by_value = {a.value.lower(): a for a in source_assets}

    def add_node(kind, label, confidence, risk_score=0):
        nid = node_id(kind, label)
        existing = nodes.get(nid)
        if existing and risk_score <= existing.risk_score and confidence <= existing.confidence:
            return nid
        nodes[nid] = GraphNode(
            nid,
            kind,
            label,
            confidence,
            risk_score,
            risk_band(risk_score) if risk_score else "unknown",
        )
        return nid

    domain_id = add_node("domain", target, 100)
    for asset in assets:
        source = by_value.get(asset.value.lower())
        score = _risk_for(source, findings)
        if source is not None:
            asset_findings=[f for f in findings if f.asset_id==source.id and f.status=="open"]
            if asset_findings:
                score=max([calculate_risk(f,source)["residual_score"] for f in asset_findings]+[score])
        aid = add_node(getattr(getattr(asset, "type", None), "value", getattr(asset, "asset_type", "asset")), asset.value, asset.confidence, score)
        asset_kind = getattr(getattr(asset, "type", None), "value", getattr(asset, "asset_type", "asset"))
        if asset_kind in {"subdomain", "application"}:
            edges.append(Relationship(domain_id, aid, "namespace_member", asset.confidence, "correlated discovery"))
        elif asset_kind == "service":
            edges.append(Relationship(domain_id, aid, "dns_related_service", asset.confidence, "DNS evidence"))

    internet_id = add_node("internet", "Internet", 100, 20)
    for source_asset in source_assets:
        score = _risk_for(source_asset, findings)
        asset_kind = getattr(getattr(source_asset, "type", None), "value", getattr(source_asset, "asset_type", "asset"))
        aid = next((n.id for n in nodes.values() if n.label.lower() == source_asset.value.lower()), None)
        if aid and "internet-facing" in source_asset.tags:
            edges.append(Relationship(internet_id, aid, "internet_exposed", source_asset.confidence, "asset evidence", min(100, source_asset.criticality*20)))
        for finding in findings:
            if finding.asset_id != source_asset.id or finding.status != "open":
                continue
            risk=calculate_risk(finding,source_asset)
            fid = add_node("finding", finding.title, risk["confidence"], risk["residual_score"])
            impact = risk["impact"]
            edges.append(Relationship(aid, fid, "finding_observed", risk["confidence"], "contextual risk engine", impact))

    for item in evidence:
        value = str(item.get("value", "")).strip()
        subject = str(item.get("subject", "")).strip().lower()
        kind = str(item.get("kind", ""))
        confidence = int(item.get("confidence", 0) or 0)
        source = str(item.get("source", "unknown"))

        if kind in {"a", "aaaa", "a_record", "aaaa_record"} and value:
            ip_id = add_node("ip", value, confidence)
            host_id = next((n.id for n in nodes.values() if n.label.lower() == subject), None)
            if host_id:
                edges.append(Relationship(host_id, ip_id, "resolves_to", confidence, f"{source}:{kind}"))

        if kind == "certificate_name" and value:
            host_id = next((n.id for n in nodes.values() if n.label.lower() == value.lower()), None)
            cert_id = add_node("certificate", value, confidence)
            if host_id:
                edges.append(Relationship(host_id, cert_id, "certificate_observed", confidence, "Certificate Transparency"))

        if kind.startswith("technology:") and value:
            host_id = next((n.id for n in nodes.values() if n.label.lower() == subject), None)
            tech_id = add_node("technology", value, confidence)
            if host_id:
                edges.append(Relationship(host_id, tech_id, "technology_observed", confidence, source))

        if kind == "caa" and value:
            host_id = next((n.id for n in nodes.values() if n.label.lower() == subject), None)
            caa_id = add_node("certificate-policy", value, confidence)
            if host_id:
                edges.append(Relationship(host_id, caa_id, "certificate_policy", confidence, source))

        if source in {"threat-intelligence", "threat_intel", "cti"} and value:
            host_id = next((n.id for n in nodes.values() if n.label.lower() == subject), None)
            threat_id = add_node("threat", value, confidence)
            if host_id:
                edges.append(Relationship(host_id, threat_id, "threat_observed", confidence, source))

    unique = {(e.source_id, e.target_id, e.kind): e for e in edges}
    edge_list = list(unique.values())
    risk_nodes = [n for n in nodes.values() if n.risk_score > 0 and n.kind not in {"finding", "internet", "threat", "certificate", "ip"}]
    paths = _top_risk_paths(nodes, edge_list)
    path_frequency = {}
    for p in paths:
        for nid in p["nodes"]:
            path_frequency[nid] = path_frequency.get(nid, 0) + 1
    for nid, count in path_frequency.items():
        if nid in nodes:
            nodes[nid].__dict__["choke_point_score"] = min(100, count * 20)
    asset_by_node = {node_id(getattr(getattr(a, "type", None), "value", getattr(a, "asset_type", "asset")), a.value): a for a in source_assets}
    for nid, asset in asset_by_node.items():
        if nid in nodes:
            nodes[nid].__dict__["security_controls"] = _security_controls(asset)
            nodes[nid].__dict__["control_coverage"] = ("covered" if nodes[nid].__dict__["security_controls"] else "unknown")
    for p in paths:
        p["choke_points"] = sorted([{"node_id": nid, "label": nodes[nid].label, "score": nodes[nid].__dict__.get("choke_point_score", 0)} for nid in p["nodes"] if nodes[nid].__dict__.get("choke_point_score", 0) > 0], key=lambda x: x["score"], reverse=True)
        p["control_summary"] = {"covered": sum(1 for nid in p["nodes"] if nodes[nid].__dict__.get("control_coverage") == "covered"), "unknown": sum(1 for nid in p["nodes"] if nodes[nid].__dict__.get("control_coverage") == "unknown")}

    return {
        "nodes": [n.__dict__ for n in nodes.values()],
        "edges": [e.__dict__ for e in edge_list],
        "risk_summary": {
            "critical": sum(1 for n in risk_nodes if n.risk_band == "critical"),
            "high": sum(1 for n in risk_nodes if n.risk_band == "high"),
            "medium": sum(1 for n in risk_nodes if n.risk_band == "medium"),
            "low": sum(1 for n in risk_nodes if n.risk_band == "low"),
            "highest_score": max((n.risk_score for n in risk_nodes), default=0),
            "risk_paths": len(paths),
            "business_impact": max((e.impact for e in edge_list), default=0),
        },
        "top_risk_paths": paths,
    }


def simulate_remediation(nodes, edges, path, remove_finding_ids=None):
    remove_finding_ids = set(remove_finding_ids or [])
    remaining_edges = [e for e in edges if not (e.target_id in remove_finding_ids and e.kind == "finding_observed")]
    before = _path_score(nodes, edges, path)
    after = _path_score(nodes, remaining_edges, path)
    reduction = max(0, before - after)
    return {"before": before, "after": after, "risk_reduction": reduction, "reduction_percent": round(reduction / before * 100) if before else 0}


def remediation_options(nodes, edges, paths, limit=8):
    options = []
    seen = set()
    for path_item in paths:
        path = path_item.get("nodes", [])
        finding_ids = [n for n in path if nodes.get(n) and nodes[n].kind == "finding"]
        for finding_id in finding_ids:
            if finding_id in seen:
                continue
            seen.add(finding_id)
            sim = simulate_remediation(nodes, edges, path, [finding_id])
            finding = nodes[finding_id]
            options.append({
                "finding_node_id": finding_id,
                "finding": finding.label,
                "severity": finding.risk_band,
                "paths_affected": sum(1 for p in paths if finding_id in p.get("nodes", [])),
                **sim,
                "priority_score": min(100, round(sim["risk_reduction"] * 0.7 + finding.confidence * 0.3)),
            })
    options.sort(key=lambda x:(x["priority_score"],x["paths_affected"]), reverse=True)
    return options[:limit]

def build_attack_surface_graph(target: str, assets, evidence: list[dict]):
    return build_risk_graph(target, assets, evidence)


RELATIONSHIPS = []
