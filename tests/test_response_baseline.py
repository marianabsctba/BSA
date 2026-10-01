from app.collectors.http import build_response_baseline, compare_response_to_baseline

def test_response_baseline_identifies_dominant_negative():
    b=build_response_baseline([
      {"status":404,"sha256":"aaa","length":10},
      {"status":404,"sha256":"aaa","length":10},
      {"status":403,"sha256":"bbb","length":20},
    ])
    assert b["dominant_hash"]=="aaa"
    assert b["dominant_count"]==2

def test_response_compare_marks_known_negative():
    b=build_response_baseline([{"status":404,"sha256":"aaa","length":10}])
    out=compare_response_to_baseline({"status":200,"sha256":"aaa","length":10},b)
    assert out["is_known_negative"] is True
    assert out["same_as_dominant"] is True
