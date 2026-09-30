from dataclasses import dataclass
from hashlib import sha256

@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    confidence: int

@dataclass(frozen=True)
class Relationship:
    source_id: str
    target_id: str
    kind: str
    confidence: int
    evidence: str

def node_id(kind: str, value: str) -> str:
    return sha256(f'{kind}:{value.lower()}'.encode()).hexdigest()[:16]

def build_attack_surface_graph(target: str, assets, evidence: list[dict]):
    nodes = {}
    edges = []
    def add_node(kind, label, confidence):
        nid = node_id(kind, label)
        nodes.setdefault(nid, GraphNode(nid, kind, label, confidence))
        return nid
    domain_id = add_node('domain', target, 100)
    for asset in assets:
        aid = add_node(asset.asset_type, asset.value, asset.confidence)
        if asset.asset_type in {'subdomain', 'application'}:
            edges.append(Relationship(domain_id, aid, 'namespace_member', asset.confidence, 'correlated discovery'))
        elif asset.asset_type == 'service':
            edges.append(Relationship(domain_id, aid, 'dns_related_service', asset.confidence, 'DNS evidence'))
    by_value = {n.label.lower(): n.id for n in nodes.values()}
    for item in evidence:
        value = str(item.get('value', '')).strip()
        subject = str(item.get('subject', '')).strip().lower()
        kind = str(item.get('kind', ''))
        confidence = int(item.get('confidence', 0) or 0)
        if kind in {'a', 'aaaa'} and value:
            ip_id = add_node('ip', value, confidence)
            host_id = by_value.get(subject)
            if host_id:
                edges.append(Relationship(host_id, ip_id, 'resolves_to', confidence, f"{item.get('source')}:{kind}"))
        if kind == 'certificate_name' and value:
            host_id = by_value.get(value.lower())
            cert_id = add_node('certificate', value, confidence)
            if host_id:
                edges.append(Relationship(host_id, cert_id, 'certificate_observed', confidence, 'Certificate Transparency'))
    unique = {(e.source_id, e.target_id, e.kind): e for e in edges}
    return {'nodes': [n.__dict__ for n in nodes.values()], 'edges': [e.__dict__ for e in unique.values()]}

RELATIONSHIPS = []