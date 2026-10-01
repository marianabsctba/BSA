import socket
import ssl
from datetime import datetime, timezone
import hashlib

from .base import Evidence
from ..security import validate_external_target


class TLSCollector:
    name = "tls"

    def collect(self, target: str, port: int = 443, timeout: float = 3.0) -> list[Evidence]:
        host, _ = validate_external_target(target)
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                protocol = tls.version()

        evidence = [
            Evidence(self.name, target, "tls_protocol", protocol or "unknown", 98),
            Evidence(self.name, target, "tls_cipher", cipher[0] if cipher else "unknown", 95),
        ]

        if cert:
            der = tls.getpeercert(binary_form=True)
            if der:
                evidence.append(Evidence(self.name,target,"certificate_sha256",hashlib.sha256(der).hexdigest(),99))
            san = []
            for item in cert.get("subjectAltName", []):
                if len(item) == 2 and item[0] == "DNS": san.append(item[1].lower())
            if san:
                evidence.append(Evidence(self.name,target,"certificate_san", ",".join(sorted(set(san)))[:2000],98,{"count":len(set(san))}))
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
