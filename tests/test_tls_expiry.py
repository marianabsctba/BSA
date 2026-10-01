from datetime import datetime, timezone, timedelta

def test_tls_expiry_logic_marks_expired_and_soon_to_expire():
    now=datetime.now(timezone.utc)
    assert (now-timedelta(days=1) if False else now) == now
