"""Deriving template values (domain/url/host) from a target name."""

from optio.context import target_values


def test_bare_host():
    v = target_values("example.com")
    assert v["domain"] == "example.com"
    assert v["url"] == "https://example.com"
    assert v["host"] == "example.com"


def test_strips_scheme_and_path():
    v = target_values("https://example.com/app?x=1")
    assert v["domain"] == "example.com"
    assert v["host"] == "example.com"


def test_keeps_port_in_host_not_domain():
    v = target_values("example.com:8443")
    assert v["host"] == "example.com:8443"
    assert v["domain"] == "example.com"
