"""The standalone HTTP sender + raw-request parser.

This is the request runner — the thing that lets a web engagement happen inside
Optio without dropping to curl. Pure stdlib. parse_raw is pure logic; send is
driven against a real throwaway server in a thread (no mocks — a mock would not
prove a 302 is captured instead of followed).
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from optio import http


# ── parse_raw ──────────────────────────────────────────────────────────────
def test_parse_raw_builds_url_from_host_and_path():
    raw = "GET /a/b?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    method, url, headers, body = http.parse_raw(raw)
    assert method == "GET"
    assert url == "https://example.com/a/b?x=1"
    assert headers["Accept"] == "*/*"
    assert body == ""


def test_parse_raw_keeps_body_and_post_method():
    raw = "POST /login HTTP/1.1\nHost: h.test\nContent-Type: application/json\n\n{\"u\":1}"
    method, url, headers, body = http.parse_raw(raw)
    assert method == "POST"
    assert url == "https://h.test/login"
    assert body == '{"u":1}'


def test_parse_raw_honours_scheme_override():
    raw = "GET / HTTP/1.1\nHost: h.test\n\n"
    _, url, _, _ = http.parse_raw(raw, scheme="http")
    assert url == "http://h.test/"


def test_parse_raw_rejects_empty():
    with pytest.raises(ValueError):
        http.parse_raw("")


# ── send (real server) ───────────────────────────────────────────────────────
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.test/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("X-Echo-Path", self.path)
        self.end_headers()
        self.wfile.write(b"hello-body")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(length)
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b"got:" + data)


@pytest.fixture()
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_send_get_captures_status_body_headers_timing(server):
    resp = http.send("GET", server + "/hi")
    assert resp.status == 200
    assert resp.body == "hello-body"
    assert dict(resp.headers).get("X-Echo-Path") == "/hi"
    assert resp.elapsed_ms >= 0
    assert resp.error == ""


def test_send_does_not_follow_redirects_by_default(server):
    resp = http.send("GET", server + "/redir")
    assert resp.status == 302
    assert dict(resp.headers).get("Location") == "https://elsewhere.test/"


def test_send_post_sends_body(server):
    resp = http.send("POST", server + "/echo", body="ping")
    assert resp.status == 201
    assert resp.body == "got:ping"


def test_send_unreachable_sets_error_not_raise():
    resp = http.send("GET", "http://127.0.0.1:1/nope", timeout=1.0)
    assert resp.status == 0
    assert resp.error


def test_raw_template_roundtrips_through_parse():
    tmpl = http.raw_template("ex.com", "/login")
    method, url, headers, _ = http.parse_raw(tmpl)
    assert method == "GET"
    assert url == "https://ex.com/login"
    assert headers["User-Agent"] == "optio"
