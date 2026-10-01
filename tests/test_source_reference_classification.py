from app.collectors.http import classify_source_reference

def test_source_reference_context_classification():
    assert classify_source_reference("src/config/auth.ts")=="sensitive-pattern"
    assert classify_source_reference("src/admin/internal.ts")=="sensitive-pattern"
    assert classify_source_reference("src/login/session.ts")=="identity-surface"
    assert classify_source_reference("src/api/client.ts")=="api-surface"
    assert classify_source_reference("src/components/Button.tsx")=="general"
