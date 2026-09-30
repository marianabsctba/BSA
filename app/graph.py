from dataclasses import dataclass


@dataclass(frozen=True)
class Relationship:
    source_id: str
    target_id: str
    kind: str
    confidence: int
    evidence: str


RELATIONSHIPS = [
    Relationship("ast-001", "ast-002", "dns_child", 99, "vpn.example.org pertence ao namespace example.org"),
    Relationship("ast-002", "ast-003", "resolves_to", 94, "resolução DNS correlacionada ao serviço observado"),
]
