import socket
import ssl
from datetime import datetime, timezone

from .base import Evidence


class TLSCollector:
    name = "tls"

    def collect(self, target: str, port: int = 443, timeout: float = 3.0) -> list[Evidence]:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                protocol = tls.version()

        evidence = [
            Evidence(self.name, target, "tls_protocol", protocol or "unknown", 98),
            Evidence(self.name, target, "tls_cipher", cipher[0] if cipher else "unknown", 95),
        ]

        if cert:
            not_after = cert.get("notAfter")
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            if subject.get("commonName"):
                evidence.append(Evidence(self.name, target, "certificate_cn", subject["commonName"], 98))
            if issuer.get("commonName"):
                evidence.append(Evidence(self.name, target, "certificate_issuer", issuer["commonName"], 98))
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                evidence.append(Evidence(self.name, target, "certificate_expires", expiry.isoformat(), 99))

        return evidence
