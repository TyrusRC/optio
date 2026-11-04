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


def test_confirm_finding_gates_the_client_report(server):
    _req(server, "POST", "/targets", {"name": "ex.com"})
    _, created = _req(server, "POST", "/targets/ex.com/findings",
                      {"title": "Reflected XSS", "severity": "high",
                       "impact": "Session theft"})
    fid = created["id"]

    # Suspected by default -> absent from the client report.
    _, rep = _req(server, "GET", "/targets/ex.com/report")
    assert "Reflected XSS" not in rep["markdown"]
    assert "No confirmed findings" in rep["markdown"]

    # Confirm it over the wire -> now in the client report.
    status, res = _req(server, "POST", f"/targets/ex.com/findings/{fid}/status",
                       {"status": "confirmed"})
    assert status == 200 and res["status"] == "confirmed"

    _, rep = _req(server, "GET", "/targets/ex.com/report")
    assert "Reflected XSS" in rep["markdown"]


def test_set_status_requires_status(server):
    _req(server, "POST", "/targets", {"name": "ex.com"})
    _, created = _req(server, "POST", "/targets/ex.com/findings", {"title": "t"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req(server, "POST", f"/targets/ex.com/findings/{created['id']}/status", {})
    assert exc.value.code == 400


def test_set_status_rejects_an_unknown_status(server):
    # Trust boundary: a direct API call must not be able to write an arbitrary
    # status string into a finding (the UI dropdown only offers the valid four).
    _req(server, "POST", "/targets", {"name": "ex.com"})
    _, created = _req(server, "POST", "/targets/ex.com/findings", {"title": "t"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req(server, "POST", f"/targets/ex.com/findings/{created['id']}/status",
             {"status": "banana"})
    assert exc.value.code == 400
    # the finding kept its default status, not the garbage one
    _, findings = _req(server, "GET", "/targets/ex.com/findings")
    assert findings[0]["status"] == "suspected"


def test_preview_command_shows_the_line_before_running(server):
    _req(server, "POST", "/targets", {"name": "ex.com"})
    status, prev = _req(server, "POST", "/targets/ex.com/preview-command", {"tool": "subfinder"})
    assert status == 200
    assert prev["command"].startswith("subfinder -d ex.com")
    assert prev["remembered"] is False
    # a tool needing a wordlist shows the unfilled placeholder, not an error
    _, prev2 = _req(server, "POST", "/targets/ex.com/preview-command", {"tool": "ffuf"})
    assert "{wordlist}" in prev2["command"]
    assert "wordlist" in prev2["missing"]


def test_catalog_reports_installed_flag(server):
    _, cat = _req(server, "GET", "/catalog")
    assert all("installed" in t for t in cat)
    assert all(isinstance(t["installed"], bool) for t in cat)


def test_proxy_config_roundtrips_and_applies_to_runner(server):
    _req(server, "POST", "/targets", {"name": "ex.com"})
    _req(server, "POST", "/targets/ex.com/config",
         {"config": {"proxy": "http://127.0.0.1:8080", "verify_tls": False,
                     "user_agent": "optio"}})
    _, cfg = _req(server, "GET", "/targets/ex.com/config")
    assert cfg["proxy"] == "http://127.0.0.1:8080"
    assert cfg["verify_tls"] is False
    # proxy is stored on the target row so tools inherit it too
    _, tgt = _req(server, "GET", "/targets/ex.com")
    assert tgt["proxy"] == "http://127.0.0.1:8080"


def test_ingest_creates_target_records_request_and_seeds_surface(server):
    status, res = _req(server, "POST", "/ingest", {
        "method": "GET", "url": "https://shop.acme.test/cart?id=1",
        "status": 200, "resp_body": "ok"})
    assert status == 200
    assert res["target"] == "shop.acme.test"
    # target was auto-created
    _, targets = _req(server, "GET", "/targets")
    assert any(t["name"] == "shop.acme.test" for t in targets)
    # request captured (query stripped from the endpoint, kept on the request url)
    _, reqs = _req(server, "GET", "/targets/shop.acme.test/requests")
    assert reqs and reqs[0]["url"] == "https://shop.acme.test/cart?id=1"
    # surface seeded: host + endpoint
    _, surface = _req(server, "GET", "/targets/shop.acme.test/surface")
    values = {n["value"] for n in surface["nodes"]}
    assert "shop.acme.test" in values
    assert "shop.acme.test/cart" in values


def test_ingest_requires_url(server):
    _, res = _req(server, "POST", "/ingest", {"method": "GET"})
    assert "error" in res
