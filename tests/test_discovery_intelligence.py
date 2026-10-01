from app.collectors.rdap import RDAPCollector
from app.collectors.dns import DNSCollector

def test_rdap_collector_has_passive_evidence_contract():
    collector=RDAPCollector()
    assert collector.name=="rdap"

def test_dns_record_types_cover_high_value_records():
    from app.collectors.dns import RECORD_TYPES
    for item in ("A","AAAA","CNAME","MX","NS","TXT","SRV"):
        assert item in RECORD_TYPES
