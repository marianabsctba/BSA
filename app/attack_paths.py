from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class AttackEdge:
    source: str
    target: str
    relation: str
    confidence: int
    evidence_refs: tuple[str,...] = ()

@dataclass(frozen=True)
class AttackPath:
    nodes: tuple[str,...]
    edges: tuple[AttackEdge,...]
    score: int
    confidence: int
    reasons: tuple[str,...]

def build_evidence_graph(edges: Iterable[AttackEdge]) -> dict[str,list[AttackEdge]]:
    graph={}
    for edge in edges:
        if not edge.source or not edge.target or edge.source==edge.target:
            continue
        if not 0 <= edge.confidence <= 100:
            continue
        if not edge.evidence_refs:
            continue
        graph.setdefault(edge.source,[]).append(edge)
    return graph

def find_paths(edges: Iterable[AttackEdge], start: str, goals: set[str], max_hops: int = 6) -> list[AttackPath]:
    graph=build_evidence_graph(edges)
    results=[]
    if max_hops < 1 or not start:
        return results

    def walk(node, nodes, used, path_edges):
        if len(path_edges) >= max_hops:
            return
        for edge in graph.get(node,()):
            if edge.target in nodes:
                continue
            next_nodes=nodes+(edge.target,)
            next_edges=path_edges+(edge,)
            if edge.target in goals:
                confidence=min(e.confidence for e in next_edges)
                score=round(sum(e.confidence for e in next_edges)/len(next_edges))
                results.append(AttackPath(next_nodes,next_edges,score,confidence,(
                    "caminho sustentado por evidências observadas",
                    f"{len(next_edges)} relacionamento(s) evidenciado(s)",
                )))
            walk(edge.target,next_nodes,used|{edge.target},next_edges)

    walk(start,(start,),{start},())
    results.sort(key=lambda p:(p.score,p.confidence,-len(p.edges)),reverse=True)
    return results

def correlate_finding_paths(edges: Iterable[AttackEdge], finding_asset_id: str, exposed_asset_ids: set[str], max_hops: int = 6) -> list[AttackPath]:
    """Correlate a finding asset with exposed assets; never invent an edge."""
    return find_paths(edges,finding_asset_id,exposed_asset_ids,max_hops)


def paths_from_risk_graph(graph: dict, start_kinds: set[str] | None = None,
                          goal_kinds: set[str] | None = None, max_hops: int = 6) -> list[AttackPath]:
    """Convert the evidence-backed risk graph into explicit attack-path candidates."""
    start_kinds = start_kinds or {"internet", "threat"}
    goal_kinds = goal_kinds or {"finding", "critical_asset"}
    nodes = {n.get("id"): n for n in graph.get("nodes", []) if n.get("id")}
    edges = []
    for raw in graph.get("edges", []):
        source, target = nodes.get(raw.get("source_id")), nodes.get(raw.get("target_id"))
        if not source or not target:
            continue
        refs = tuple(raw.get("evidence_refs") or ())
        if not refs and raw.get("evidence"):
            refs = (str(raw["evidence"]),)
        edges.append(AttackEdge(
            source=raw["source_id"], target=raw["target_id"],
            relation=str(raw.get("kind","related")),
            confidence=int(raw.get("confidence",0) or 0),
            evidence_refs=refs,
        ))
    goals={nid for nid,n in nodes.items() if n.get("kind") in goal_kinds}
    paths=[]
    for nid,n in nodes.items():
        if n.get("kind") not in start_kinds:
            continue
        paths.extend(find_paths(edges,nid,goals,max_hops))
    return paths
