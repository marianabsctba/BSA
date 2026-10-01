from datetime import datetime, timezone, timedelta
from app.collectors.tls import classify_certificate_expiry

def test_tls_expiry_classification():
    now=datetime(2026,1,1,tzinfo=timezone.utc)
    assert classify_certificate_expiry(now-timedelta(days=1),now)[0]=="expired"
    assert classify_certificate_expiry(now+timedelta(days=10),now)[0]=="expiring_soon"
    assert classify_certificate_expiry(now+timedelta(days=60),now)[0]=="valid"
