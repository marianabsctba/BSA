from app.collectors.http import extract_openapi_inventory

def test_openapi_inventory_extracts_methods_and_auth():
    body=b'{"openapi":"3.0.0","security":[{"bearerAuth":[]}],"paths":{"/users":{"get":{"operationId":"listUsers"},"post":{"operationId":"createUser","security":[]}},"/health":{"get":{}}}}'
    ev=extract_openapi_inventory("https://example.org/openapi.json",body)
    assert len(ev)==3
    users_get=next(x for x in ev if x.value=="/users" and x.metadata["method"]=="GET")
    users_post=next(x for x in ev if x.value=="/users" and x.metadata["method"]=="POST")
    assert users_get.metadata["auth_declared"] is True
    assert users_post.metadata["auth_declared"] is False
