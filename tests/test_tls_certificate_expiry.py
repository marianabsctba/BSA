def test_tls_expired_certificate_is_evidence():
    from app.collectors.tls import classify_certificate_expiry
    from datetime import datetime, timezone, timedelta
    now=datetime(2026,10,1,tzinfo=timezone.utc)
    status,days=classify_certificate_expiry(now-timedelta(days=2),now)
    assert status=="expired"
    assert days < 0


def test_tls_expiring_soon_is_evidence_class():
    from app.collectors.tls import classify_certificate_expiry
    from datetime import datetime, timezone, timedelta
    now=datetime(2026,10,1,tzinfo=timezone.utc)
    status,days=classify_certificate_expiry(now+timedelta(days=7),now)
    assert status=="expiring_soon"
    assert 6 < days < 8
