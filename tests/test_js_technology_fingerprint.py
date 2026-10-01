def test_js_technology_fingerprint_react_version():
    from app.collectors.http import detect_js_technology_fingerprints
    js="react.transitional.element React.Component react-dom 19.2.3"
    findings=detect_js_technology_fingerprints(js,'https://example.org/assets/index.js')
    versions=[f for f in findings if f.kind=='technology_version']
    assert any(f.value=='react:19.2.3' for f in versions)

def test_js_technology_fingerprint_does_not_execute_code():
    from app.collectors.http import detect_js_technology_fingerprints
    js="fetch(\"https://evil.invalid\"); React.Fragment; webpack-runtime"
    findings=detect_js_technology_fingerprints(js,'https://example.org/assets/index.js')
    assert any(f.kind=='technology_fingerprint' and f.value=='react' for f in findings)
    assert any(f.kind=='build_tool_fingerprint' and f.value=='webpack' for f in findings)