from app.ip_intelligence import classify_ip,ip_exposure_signal

def test_ip_classification():
    assert classify_ip("10.0.0.1")=="private"
    assert classify_ip("127.0.0.1")=="loopback"
    assert ip_exposure_signal("8.8.8.8")["externally_routable"] is True
