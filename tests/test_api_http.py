"""API routes for the request runner, captures, and report."""

import pytest

from optio import http
from optio.api import _NotFound, _route
from optio.service import OptioService
from optio.store import Store


def _svc(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com", tech=["php"])

    def sender(method, url, headers=None, body=None, proxy=None, **kw):
        return http.HttpResponse(status=200, headers=[("Server", "nginx")],
                                 body="pong", elapsed_ms=5)

    return OptioService(s, catalog=[], pipelines=[], http_send=sender), s


def test_post_request_sends_and_captures(tmp_path):
    svc, store = _svc(tmp_path)
    out = _route(svc, "POST", "/targets/ex.com/request",
                 {"method": "GET", "url": "https://ex.com/a"})
    assert out["status"] == 200 and out["request_id"]
    rows = _route(svc, "GET", "/targets/ex.com/requests", {})
    assert rows[0]["url"] == "https://ex.com/a"
    store.close()


def test_get_single_request(tmp_path):
    svc, store = _svc(tmp_path)
    out = _route(svc, "POST", "/targets/ex.com/request",
                 {"method": "GET", "url": "https://ex.com/a"})
    one = _route(svc, "GET", f"/targets/ex.com/requests/{out['request_id']}", {})
    assert one["resp_body"] == "pong"
    with pytest.raises(_NotFound):
        _route(svc, "GET", "/targets/ex.com/requests/9999", {})
    store.close()


def test_post_request_raw(tmp_path):
    svc, store = _svc(tmp_path)
    raw = "GET /x HTTP/1.1\nHost: ex.com\n\n"
    out = _route(svc, "POST", "/targets/ex.com/request-raw", {"raw": raw})
    assert out["status"] == 200
    store.close()


def test_get_report(tmp_path):
    svc, store = _svc(tmp_path)
    svc.add_finding("ex.com", title="IDOR", status="confirmed", severity="high",
                    impact="reads others")
    md = _route(svc, "GET", "/targets/ex.com/report", {})
    assert "IDOR" in md["markdown"]
    store.close()


def test_findings_post_accepts_report_fields(tmp_path):
    svc, store = _svc(tmp_path)
    _route(svc, "POST", "/targets/ex.com/findings",
           {"title": "IDOR", "severity": "high", "impact": "reads others",
            "remediation": "check ownership", "cwe": "CWE-639"})
    f = store.findings_for_target("ex.com")[0]
    assert f["impact"] == "reads others" and f["cwe"] == "CWE-639"
    store.close()
