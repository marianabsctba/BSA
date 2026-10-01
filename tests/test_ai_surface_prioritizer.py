from app.local_ai import prioritize_surface_candidates

def test_ai_surface_prioritizer_is_fail_closed():
    result=prioritize_surface_candidates([
      {"url":"https://example.org/admin","classification":"interesting"},
      {"url":"https://example.org/x","classification":"negative-known"},
    ],[])
    assert result is None or isinstance(result,dict)
    if result:
        assert "priorities" in result
        assert "discarded" in result
        assert "unknowns" in result
