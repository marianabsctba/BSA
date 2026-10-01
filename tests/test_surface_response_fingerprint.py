from app.collectors.http import classify_surface_response

def test_surface_response_fingerprint_captures_status_type_length_and_hash():
    info=classify_surface_response(200,{"content-type":"text/html; charset=utf-8"},b"same")
    assert info["status"]==200
    assert info["content_type"]=="text/html"
    assert info["length"]==4
    assert info["sha256"]
    assert info["redirect"] is False

def test_surface_response_detects_redirect():
    info=classify_surface_response(302,{"content-type":"text/html"},b"x")
    assert info["redirect"] is True
