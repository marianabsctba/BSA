from app.local_ai import prioritize_collection

def test_ai_collection_prioritizer_fails_closed():
    result=prioritize_collection("example.org",[],[],["dns","http","tls"])
    assert result is None or isinstance(result,dict)
    if result:
        assert "priorities" in result
        assert "evidence_gaps" in result
        assert "confidence" in result
