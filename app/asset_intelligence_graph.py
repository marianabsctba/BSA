"""Asset Intelligence Graph foundation for Be Safe ASM.

Internal knowledge layer. It does not expose collection engines to users.
It stores relationships between business assets, infrastructure, technology,
evidence and exposure context.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List
import uuid


@dataclass
class AssetNode:
    node_id: str
    node_type: str
    name: str
    attributes: Dict = field(default_factory=dict)


@dataclass
class AssetRelationship:
    source: str
    target: str
    relation: str
    confidence: int = 0


class AssetIntelligenceGraph:
    """Internal graph model used for exposure intelligence correlation."""

    def __init__(self):
        self.nodes: Dict[str, AssetNode] = {}
        self.edges: List[AssetRelationship] = []

    def add_node(self, node_type: str, name: str, attributes=None) -> str:
        node_id = str(uuid.uuid4())
        self.nodes[node_id] = AssetNode(
            node_id=node_id,
            node_type=node_type,
            name=name,
            attributes=attributes or {},
        )
        return node_id

    def link(self, source: str, target: str, relation: str, confidence: int = 0):
        self.edges.append(
            AssetRelationship(
                source=source,
                target=target,
                relation=relation,
                confidence=confidence,
            )
        )

    def explain_asset_context(self, node_id: str) -> dict:
        related = [
            asdict(edge)
            for edge in self.edges
            if edge.source == node_id or edge.target == node_id
        ]

        return {
            "asset_context_id": node_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "relationships": related,
            "relationship_count": len(related),
        }
