"""The web UI server — static SPA + JSON API over one loopback port.

static_file is pure (path resolution + traversal guard). The server is driven
live against a real socket: GET / serves the SPA, GET /targets returns JSON
through the shared dispatch.
"""

import json
import threading
import urllib.request

import pytest

from optio import web
from optio.service import OptioService
from optio.store import Store


# ── static_file (pure) ───────────────────────────────────────────────────────
def test_static_file_serves_index_at_root():
    out = web.static_file("/")
    assert out is not None
    data, ctype = out
    assert b"<title>Optio" in data
    assert ctype == "text/html"


def test_static_file_serves_app_js():
    out = web.static_file("/static/app.js")
    assert out and out[1] in ("text/javascript", "application/javascript")


def test_static_file_rejects_non_static_paths():
    assert web.static_file("/targets") is None  # API path, not a file


def test_static_file_rejects_traversal():
    assert web.static_file("/static/../../store.py") is None


# ── live server ──────────────────────────────────────────────────────────────
@pytest.fixture()
def server(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add_target("ex.com", tech=["php"])
    svc = OptioService(store, catalog=[], pipelines=[], ranker=lambda o, t, k: None)
    srv = web.make_web_server(svc, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    store.close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.headers.get_content_type(), r.read()


def test_server_serves_spa(server):
    status, ctype, body = _get(server + "/")
    assert status == 200 and ctype == "text/html"
    assert b"id=\"graph\"" in body


def test_server_serves_json_api(server):
    status, ctype, body = _get(server + "/targets")
    assert status == 200 and ctype == "application/json"
    assert any(t["name"] == "ex.com" for t in json.loads(body))


def test_server_serves_surface_graph(server):
    status, _, body = _get(server + "/targets/ex.com/surface")
    g = json.loads(body)
    assert "nodes" in g and "edges" in g
