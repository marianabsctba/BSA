from app.collectors.http import classify_surface_candidate

def test_surface_candidate_uses_negative_baseline():
    b={"known_hashes":{"aaa":2},"dominant_hash":"aaa","dominant_count":2}
    assert classify_surface_candidate({"status":200,"sha256":"aaa","redirect":False},b)=="negative-known"
    assert classify_surface_candidate({"status":302,"sha256":"bbb","redirect":True},b)=="redirect"
    assert classify_surface_candidate({"status":200,"sha256":"bbb","redirect":False},b)=="interesting"
    assert classify_surface_candidate({"status":401,"sha256":"bbb","redirect":False},b)=="protected"
