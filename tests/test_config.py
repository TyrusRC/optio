"""Per-target config — custom headers and User-Agent applied to requests.

The operator sets a header set (and UA) once per target; the request runner
merges them as defaults so every send looks like the intended client. Explicit
per-request headers always win. Persists across sessions in the target row.
"""

from optio import http
from optio.service import OptioService
from optio.store import Store


def test_config_roundtrips_on_target(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    s.set_config("ex.com", {"headers": {"X-Env": "staging"}, "user_agent": "optio/1"})
    assert s.get_target("ex.com")["config"]["user_agent"] == "optio/1"
    s.close()


def test_old_targets_table_migrates(tmp_path):
    import sqlite3
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE targets (name TEXT PRIMARY KEY, tech TEXT NOT NULL DEFAULT '[]',"
        " notes TEXT DEFAULT '', proxy TEXT DEFAULT '', artifacts_dir TEXT DEFAULT '',"
        " created_at REAL NOT NULL);")
    con.execute("INSERT INTO targets(name, created_at) VALUES ('ex.com', 1.0)")
    con.commit(); con.close()
    s = Store(db)  # must not raise, gains the config column
    assert s.get_target("ex.com")["config"] == {}
    s.close()


def _svc(tmp_path, sender):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    s.set_config("ex.com", {"headers": {"X-Env": "staging"}, "user_agent": "optio-ua"})
    return OptioService(s, catalog=[], pipelines=[], http_send=sender, ranker=lambda o, t, k: None), s


def test_send_request_applies_config_headers_and_ua(tmp_path):
    seen = {}

    def sender(method, url, headers=None, body=None, proxy=None, **kw):
        seen["headers"] = headers
        return http.HttpResponse(status=200, body="", elapsed_ms=1)

    svc, store = _svc(tmp_path, sender)
    svc.send_request("ex.com", "GET", "https://ex.com/")
    assert seen["headers"]["X-Env"] == "staging"
    assert seen["headers"]["User-Agent"] == "optio-ua"
    store.close()


def test_explicit_header_overrides_config(tmp_path):
    seen = {}

    def sender(method, url, headers=None, body=None, proxy=None, **kw):
        seen["headers"] = headers
        return http.HttpResponse(status=200, body="", elapsed_ms=1)

    svc, store = _svc(tmp_path, sender)
    svc.send_request("ex.com", "GET", "https://ex.com/", headers={"User-Agent": "mine"})
    assert seen["headers"]["User-Agent"] == "mine"      # caller wins
    assert seen["headers"]["X-Env"] == "staging"        # config still merged
    store.close()
