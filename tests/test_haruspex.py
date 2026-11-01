"""The optional Haruspex ranking hint — local, keyless, fail-open.

Optio works fully without Haruspex. When it is unreachable, every call returns
None (no hint), never an exception, and quickly.
"""

from optio import haruspex


def test_default_url_prefers_env(monkeypatch):
    monkeypatch.setenv("HARUSPEX_URL", "http://127.0.0.1:4321")
    assert haruspex.default_url() == "http://127.0.0.1:4321"


def test_default_url_falls_back_to_praetor_var(monkeypatch):
    monkeypatch.delenv("HARUSPEX_URL", raising=False)
    monkeypatch.setenv("PRAETOR_DECISION_BASE_URL", "http://127.0.0.1:5555")
    assert haruspex.default_url() == "http://127.0.0.1:5555"


def test_default_url_default_is_local_3000(monkeypatch):
    monkeypatch.delenv("HARUSPEX_URL", raising=False)
    monkeypatch.delenv("PRAETOR_DECISION_BASE_URL", raising=False)
    assert haruspex.default_url() == "http://127.0.0.1:3000"


def test_evaluate_unreachable_returns_none(monkeypatch):
    # port 9 (discard) refuses fast; fail-open must give None, not raise
    monkeypatch.setenv("HARUSPEX_URL", "http://127.0.0.1:9")
    out = haruspex.evaluate("which next?", {"a": "A", "b": "B"}, target="ex.com", timeout=0.5)
    assert out is None


def test_rank_candidates_unreachable_returns_none(monkeypatch):
    monkeypatch.setenv("HARUSPEX_URL", "http://127.0.0.1:9")
    out = haruspex.rank_candidates("which next?", ["a", "b"], target="ex.com", timeout=0.5)
    assert out is None
