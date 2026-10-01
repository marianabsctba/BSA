def test_technical_change_categories():
    from app.technical_change_intelligence import classify_technical_category
    assert classify_technical_category("hostname","api.example.org")=="dns"
    assert classify_technical_category("port","tcp/443")=="service"
    assert classify_technical_category("certificate","CERT-1")=="tls"
    assert classify_technical_category("technology","React")=="technology"
    assert classify_technical_category("endpoint","/api/users")=="endpoint"

def test_technical_normalization_avoids_false_change_from_case_and_trailing_dot():
    from app.technical_change_intelligence import compare_technical_snapshots
    from app.deep_discovery import DiscoveryPivot
    b=[DiscoveryPivot("hostname","API.Example.Org.","dns",90,"e1")]
    a=[DiscoveryPivot("hostname","api.example.org","dns",90,"e1")]
    assert compare_technical_snapshots(b,a)==[]
