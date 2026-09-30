from dataclasses import dataclass
from hashlib import sha256

@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    confidence: int
    risk_score: int = 0
    risk_band: str = 'unknown'

@dataclass(frozen=True)
class Relationship:
    source_id: str
    target_id: str
    kind: str
    confidence: int
    evidence: str

def node_id(kind: str, value: str) -> str:
    return sha256(f'{kind}:{value.lower()}'.encode()).hexdigest()[:16]

def risk_band(score: int) -> str:
    if score >= 85: return 'critical'
    if score >= 70: return 'high'
    if score >= 45: return 'medium'
    return 'low'

def _risk_for(asset, findings):
    if asset is None:
        return 0
    score = min(20, asset.criticality * 4) + round(asset.confidence * 0.10)
    if 'internet-facing' in asset.tags: score += 18
    if 'remote-access' in asset.tags: score += 8
    if 'candidate' in asset.tags or 'shadow' in asset.tags: score += 10
    points = {'info': 0, 'low': 4, 'medium': 9, 'high': 15, 'critical': 20}
    for finding in findings or []:
        if finding.asset_id == asset.id and finding.status == 'open':
            score += points.get(finding.severity.value, 0)
    return min(100, score)

def build_risk_graph(target: str, assets, evidence: list[dict], source_assets=None, findings=None):
    nodes = {}
    edges = []
    source_assets = source_assets or []
    findings = findings or []
    by_value = {a.value.lower(): a for a in source_assets}

    def add_node(kind, label, confidence, risk_score=0):
        nid = node_id(kind, label)
        existing = nodes.get(nid)
        if existing and risk_score <= existing.risk_score:
            return nid
        nodes[nid] = GraphNode(nid, kind, label, confidence, risk_score, risk_band(risk_score) if risk_score else 'unknown')
        return nid

    domain_id = add_node('domain', target, 100)
    for asset in assets:
        source = by_value.get(asset.value.lower())
        score = _risk_for(source, findings)
        aid = add_node(asset.asset_type, asset.value, asset.confidence, score)
        if asset.asset_type in {'subdomain', 'application'}:
            edges.append(Relationship(domain_id, aid, 'namespace_member', asset.confidence, 'correlated discovery'))
        elif asset.asset_type == 'service':
            edges.append(Relationship(domain_id, aid, 'dns_related_service', asset.confidence, 'DNS evidence'))

    for item in evidence:
        value = str(item.get('value', '')).strip()
        subject = str(item.get('subject', '')).strip().lower()
        kind = str(item.get('kind', ''))
        confidence = int(item.get('confidence', 0) or 0)
        source = str(item.get('source', 'unknown'))
        if kind in {'a', 'aaaa'} and value:
            ip_id = add_node('ip', value, confidence)
            host_id = next((n.id for n in nodes.values() if n.label.lower() == subject), None)
            if host_id:
                edges.append(Relationship(host_id, ip_id, 'resolves_to', confidence, f'{source}:{kind}'))
        if kind == 'certificate_name' and value:
            host_id = next((n.id for n in nodes.values() if n.label.lower() == value.lower()), None)
            cert_id = add_node('certificate', value, confidence)
            if host_id:
                edges.append(Relationship(host_id, cert_id, 'certificate_observed', confidence, 'Certificate Transparency'))
        if source in {'threat-intelligence', 'threat_intel', 'cti'} and value:
            host_id = next((n.id for n in nodes.values() if n.label.lower() == subject), None)
            threat_id = add_node('threat', value, confidence, 0)
            if host_id:
                edges.append(Relationship(host_id, threat_id, 'threat_observed', confidence, source))

    unique = {(e.source_id, e.target_id, e.kind): e for e in edges}
    risk_nodes = [n for n in nodes.values() if n.risk_score > 0]
    return {
        'nodes': [n.__dict__ for n in nodes.values()],
        'edges': [e.__dict__ for e in unique.values()],
        'risk_summary': {
            'critical': sum(1 for n in risk_nodes if n.risk_band == 'critical'),
            'high': sum(1 for n in risk_nodes if n.risk_band == 'high'),
            'medium': sum(1 for n in risk_nodes if n.risk_band == 'medium'),
            'low': sum(1 for n in risk_nodes if n.risk_band == 'low'),
            'highest_score': max((n.risk_score for n in risk_nodes), default=0),
        },
    }

def build_attack_surface_graph(target: str, assets, evidence: list[dict]):
    return build_risk_graph(target, assets, evidence)

RELATIONSHIPS = []