import socket
import ssl
from datetime import datetime, timezone
import hashlib

from .base import Evidence
from ..security import validate_external_target


def classify_certificate_expiry(expiry: datetime, now: datetime | None = None) -> tuple[str,float]:
    now=now or datetime.now(timezone.utc)
    days=(expiry-now).total_seconds()/86400
    return ("expired" if days < 0 else "expiring_soon" if days <= 30 else "valid", days)

class TLSCollector:
    name = "tls"

    def collect(self, target: str, port: int = 443, timeout: float = 3.0) -> list[Evidence]:
        host, _ = validate_external_target(target)
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                protocol = tls.version()

        evidence = [
            Evidence(self.name, target, "tls_protocol", protocol or "unknown", 98),
            Evidence(self.name, target, "tls_cipher", cipher[0] if cipher else "unknown", 95),
        ]

        if cert:
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
                status,days=classify_certificate_expiry(expiry)
                evidence.append(Evidence(self.name, target, "certificate_expires", expiry.isoformat(), 99,
                                          {"days_remaining":round(days,1),"expired":status=="expired"}))
                evidence.append(Evidence(self.name,target,"certificate_expiry_status",status,99,
                                          {"days_remaining":round(days,1)}))

        return evidence
