from app.collectors.http import detect_frontend_build_markers

def test_frontend_build_markers_detect_next_and_assets():
    body=b'''<html><script id="__NEXT_DATA__"></script><script src="/_next/static/chunks/app.js"></script></html>'''
    ev=detect_frontend_build_markers(body,"https://example.org/")
    assert any(x.kind=="frontend_framework_marker" and x.value=="nextjs" for x in ev)
    assert any(x.kind=="frontend_build_asset" for x in ev)

def test_frontend_build_markers_is_bounded():
    ev=detect_frontend_build_markers(b"webpack webpack webpack", "https://example.org/")
    assert len(ev)<=200
