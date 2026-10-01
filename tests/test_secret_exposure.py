def test_secret_detection_never_stores_raw_value():
    from app.collectors.http import detect_potential_secrets
    raw='api_key=SUPER_SECRET_VALUE_123456789'
    findings=detect_potential_secrets(raw,'https://example.org/app.js')
    assert findings
    f=findings[0]
    assert f.kind=='potential_secret_exposure'
    assert f.metadata['validation']=='suspected_only'
    assert 'SUPER_SECRET_VALUE_123456789' not in str(f.metadata)
    assert len(f.metadata['fingerprint'])==64

def test_secret_detection_private_key_and_jwt():
    from app.collectors.http import detect_potential_secrets
    raw='-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n eyJaaaaaaaa.eyJbbbbbbbb.eyJcccccccc'
    kinds={x.metadata['secret_type'] for x in detect_potential_secrets(raw,'https://example.org/app.js')}
    assert 'private_key' in kinds
    assert 'jwt' in kinds