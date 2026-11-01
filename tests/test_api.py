"""Headless HTTP API test — start the server, drive it over the wire.

No TUI. This is the automation surface: add a target, read coverage and the next
action, run a tool, read findings — all over HTTP, proven against a live server.
"""

import json
import urllib.error
import urllib.request

import pytest

from optio.api import make_server
from optio.executor import RunResult
from optio.service import OptioService
from optio.store import Store


def _fake_runner(command, proxy=None):
    return RunResult(exit_code=0, output=f"ran: {command}")


@pytest.fixture
def server(tmp_path):
    store = Store(tmp_path / "t.db")
    svc = OptioService(store, runner=_fake_runner)
    srv = make_server(svc, host="127.0.0.1", port=0)  # ephemeral port
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    yield f"http://{host}:{port}"
    srv.shutdown()
    store.close()


def _req(base, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, json.loads(r.read().decode())


def test_health(server):
    status, body = _req(server, "GET", "/health")
    assert status == 200 and body["ok"] is True


def test_add_target_then_read_coverage_and_next(server):
    _, created = _req(server, "POST", "/targets", {"name": "ex.com", "tech": ["php"]})
    assert created["name"] == "ex.com"

    _, targets = _req(server, "GET", "/targets")
    assert any(t["name"] == "ex.com" for t in targets)

    _, cov = _req(server, "GET", "/targets/ex.com/coverage")
    assert "subfinder" in cov["open"]

    _, nxt = _req(server, "GET", "/targets/ex.com/next")
    assert nxt[0]["phase"] == "recon"


def test_run_tool_over_http_executes_and_records(server):
    _req(server, "POST", "/targets", {"name": "ex.com"})
    status, res = _req(server, "POST", "/targets/ex.com/run", {"tool": "subfinder"})
    assert status == 200
    assert res["exit_code"] == 0
    assert res["command"].startswith("subfinder -d ex.com")

    _, cov = _req(server, "GET", "/targets/ex.com/coverage")
    assert "subfinder" in cov["ran"]


def test_run_pipeline_over_http(server):
    _req(server, "POST", "/targets", {"name": "ex.com"})
    status, steps = _req(server, "POST", "/targets/ex.com/run-pipeline", {"pipeline": "network"})
    assert status == 200
    assert any(s["tool"] == "groma" for s in steps)


def test_catalog_endpoint(server):
    status, cat = _req(server, "GET", "/catalog")
    assert status == 200 and any(t["name"] == "vigil" for t in cat)


def test_unknown_target_is_404(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req(server, "GET", "/targets/nope.com")
    assert exc.value.code == 404
