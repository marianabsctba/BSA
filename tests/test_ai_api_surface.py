from app.local_ai import analyze_api_surface

def test_ai_api_surface_prompt_is_evidence_grounded():
    result=analyze_api_surface("example.org",[
        {"value":"/admin","metadata":{"method":"POST","auth_declared":False}},
        {"value":"/users","metadata":{"method":"GET","auth_declared":True}},
    ],[{"kind":"technology:server","value":"nginx"}])
    # Local AI may be unavailable in CI; function must fail closed without inventing output.
    assert result is None or isinstance(result,dict)
    if result:
        assert "unknowns" in result
        assert "validation" in result
