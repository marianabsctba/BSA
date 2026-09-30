from app.scope import Scope


def test_scope_allows_root_and_child():
    scope = Scope(domains=("example.org",))
    assert scope.allows_hostname("example.org")
    assert scope.allows_hostname("vpn.example.org")


def test_scope_rejects_suffix_trick():
    scope = Scope(domains=("example.org",))
    assert not scope.allows_hostname("example.org.evil.test")
    assert not scope.allows_hostname("notexample.org")


def test_scope_url():
    scope = Scope(domains=("example.org",))
    assert scope.allows_url("https://portal.example.org/login")
    assert not scope.allows_url("https://example.net/")
