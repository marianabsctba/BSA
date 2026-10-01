from app.exposure_signals import cloud_signals,takeover_signals

def test_cloud_signals_are_conservative():
    s=cloud_signals(["app.example.amazonaws.com","unrelated.example"])
    assert any(x.value=="aws" for x in s)

def test_takeover_signals_require_validation():
    s=takeover_signals(["NoSuchBucket"])
    assert s and s[0].validation_required is True
