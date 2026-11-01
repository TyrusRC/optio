"""Service-level request runner, captures, and report.

The service sends a request through optio.http, snapshots it into the store as
durable evidence, and renders a report from findings. The HTTP sender is
injected (like the tool runner) so these tests prove the wiring without a
network.
"""

from optio import http
from optio.service import OptioService
from optio.store import Store


def _svc(tmp_path, sender):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com", tech=["php"])
    return OptioService(s, catalog=[], pipelines=[], http_send=sender), s


def _fake_sender(method, url, headers=None, body=None, proxy=None, **kw):
    return http.HttpResponse(status=200, headers=[("Server", "nginx")],
                             body="pong", elapsed_ms=12)


def test_send_request_captures_and_returns_summary(tmp_path):
    svc, store = _svc(tmp_path, _fake_sender)
    out = svc.send_request("ex.com", "GET", "https://ex.com/ping")
    assert out["status"] == 200
    assert out["request_id"]
    row = store.get_request(out["request_id"])
    assert row["url"] == "https://ex.com/ping"
    assert row["resp_body"] == "pong"
    store.close()


def test_send_raw_parses_then_sends(tmp_path):
    seen = {}

    def sender(method, url, headers=None, body=None, proxy=None, **kw):
        seen.update(method=method, url=url, body=body)
        return http.HttpResponse(status=201, body="ok", elapsed_ms=1)

    svc, store = _svc(tmp_path, sender)
    raw = "POST /login HTTP/1.1\nHost: ex.com\nContent-Type: application/json\n\n{\"u\":1}"
    out = svc.send_raw("ex.com", raw)
    assert out["status"] == 201
    assert seen["method"] == "POST"
    assert seen["url"] == "https://ex.com/login"
    assert seen["body"] == '{"u":1}'
    store.close()


def test_finding_can_cite_a_captured_request_in_the_report(tmp_path):
    svc, store = _svc(tmp_path, _fake_sender)
    out = svc.send_request("ex.com", "GET", "https://ex.com/invoice/1001")
    svc.add_finding("ex.com", title="IDOR", vuln_class="idor", endpoint="/invoice/{id}",
                    severity="high", status="confirmed", impact="reads other invoices",
                    evidence_request_id=out["request_id"])
    md = svc.report("ex.com")
    assert "IDOR" in md
    assert "GET https://ex.com/invoice/1001" in md  # evidence resolved from the store
    store.close()
