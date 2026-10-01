from app.collectors.http import extract_frontend_manifest_candidates

def test_frontend_manifest_candidates():
    body=b'''<script src="/_next/static/chunks/app.js"></script><script src="/_next/static/build-manifest.json"></script><script src="/_next/static/_buildManifest.js"></script>'''
    ev=extract_frontend_manifest_candidates(body,"https://example.org/")
    assert any(x.kind=="frontend_manifest_candidate" for x in ev)
    assert len(ev)<=200
