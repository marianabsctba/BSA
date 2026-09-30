import socket

from .base import Evidence


class DNSCollector:
    name = "dns"

    def collect(self, target: str) -> list[Evidence]:
        evidence: list[Evidence] = []
        try:
            _, aliases, addresses = socket.gethostbyname_ex(target)
        except socket.gaierror:
            return evidence

        for ip in sorted(set(addresses)):
            evidence.append(
                Evidence(
                    source=self.name,
                    subject=target,
                    kind="a_record",
                    value=ip,
                    confidence=95,
                )
            )

        for alias in sorted(set(aliases)):
            evidence.append(
                Evidence(
                    source=self.name,
                    subject=target,
                    kind="alias",
                    value=alias,
                    confidence=90,
                )
            )

        return evidence
