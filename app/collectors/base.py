from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Evidence:
    source: str
    subject: str
    kind: str
    value: str
    confidence: int
    metadata: dict = field(default_factory=dict)


class Collector(Protocol):
    name: str

    def collect(self, target: str) -> list[Evidence]:
        ...
