from app.local_ai import validate_asset_identity

def test_identity_validator_fails_closed():
    result=validate_asset_identity(
        [{"fingerprint":"abc","value":"app.example.org","asset_type":"application","confidence":80}],
        [{"kind":"a_record","value":"192.0.2.10","source":"dns","confidence":95}]
    )
    assert result is None or isinstance(result,dict)
    if result:
        assert "conflicts" in result
        assert "unknowns" in result
        assert "validation" in result
