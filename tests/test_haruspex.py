"""The optional Haruspex ranking hint — Optio-native, local, keyless, fail-open.

Optio works fully without Haruspex. When it is unreachable, every call returns
None (no hint), never an exception, and quickly. The URL comes from an
Optio-owned env var first, so a user who never touches Praetor configures Optio
with Optio's own variable.
"""

from optio import haruspex


def test_default_url_prefers_optio_native_var(monkeypatch):
    monkeypatch.setenv("OPTIO_HARUSPEX_URL", "http://optio-host:3000")
    monkeypatch.setenv("HARUSPEX_URL", "http://generic:3000")
    monkeypatch.setenv("PRAETOR_DECISION_BASE_URL", "http://praetor:3000")
    assert haruspex.default_url() == "http://optio-host:3000"


def test_default_url_falls_back_to_generic_then_praetor(monkeypatch):
    monkeypatch.delenv("OPTIO_HARUSPEX_URL", raising=False)
    monkeypatch.setenv("HARUSPEX_URL", "http://generic:3000")
    assert haruspex.default_url() == "http://generic:3000"
    monkeypatch.delenv("HARUSPEX_URL", raising=False)
    monkeypatch.setenv("PRAETOR_DECISION_BASE_URL", "http://praetor:3000")
    assert haruspex.default_url() == "http://praetor:3000"


def test_default_url_default_when_unset(monkeypatch):
    for var in ("OPTIO_HARUSPEX_URL", "HARUSPEX_URL", "PRAETOR_DECISION_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    assert haruspex.default_url() == "http://127.0.0.1:3000"


def test_evaluate_unreachable_returns_none(monkeypatch):
    # port 9 (discard) refuses fast; fail-open must give None, not raise
    monkeypatch.delenv("OPTIO_HARUSPEX_URL", raising=False)
    monkeypatch.setenv("HARUSPEX_URL", "http://127.0.0.1:9")
    out = haruspex.evaluate("which next?", {"a": "A", "b": "B"}, target="ex.com", timeout=0.5)
    assert out is None


def test_rank_candidates_unreachable_returns_none(monkeypatch):
    monkeypatch.delenv("OPTIO_HARUSPEX_URL", raising=False)
    monkeypatch.setenv("HARUSPEX_URL", "http://127.0.0.1:9")
    out = haruspex.rank_candidates("which next?", ["a", "b"], target="ex.com", timeout=0.5)
    assert out is None
