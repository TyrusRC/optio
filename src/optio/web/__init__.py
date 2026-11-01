"""Local web UI server — the attack-surface graph and free-form cockpit.

Serves a single-page app (vendored, offline-capable) plus the JSON API from
``optio.api`` over one loopback port. Stdlib ``http.server`` only. The operator
drives any flow from the browser: run any tool, any pipeline, any request, in
any order, and see the surface as a Wiz-style graph of what to find.

Entry point: ``optio-web``.
"""

from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from optio.api import dispatch
from optio.service import OptioService

_STATIC = resources.files("optio.web") / "static"
_CTYPE = {".html": "text/html", ".js": "text/javascript", ".css": "text/css",
          ".json": "application/json", ".svg": "image/svg+xml"}


def static_file(path: str) -> tuple[bytes, str] | None:
    """Resolve a static request to ``(bytes, content_type)`` or None.

    Only ``/`` (the SPA) and ``/static/...`` are served; every other path is an
    API route. Any ``..`` segment is rejected so a request cannot escape the
    static tree.
    """
    if path in ("/", "/index.html"):
        rel_parts = ["index.html"]
    elif path.startswith("/static/"):
        rel_parts = [p for p in path[len("/static/"):].split("/") if p not in ("", ".")]
    else:
        return None
    if not rel_parts or any(p == ".." for p in rel_parts):
        return None
    node = _STATIC
    for p in rel_parts:
        node = node / p
    try:
        data = node.read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError, ValueError):
        return None
    ext = "." + rel_parts[-1].rsplit(".", 1)[-1] if "." in rel_parts[-1] else ""
    ctype = _CTYPE.get(ext) or mimetypes.guess_type(rel_parts[-1])[0] or "application/octet-stream"
    return data, ctype


def _handler_class(svc: OptioService):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, data: bytes, ctype: str):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _dispatch(self, method: str):
            path = self.path.split("?", 1)[0]
            if method == "GET":
                served = static_file(path)
                if served is not None:
                    self._send(200, served[0], served[1])
                    return
            try:
                body = {}
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, KeyError) as e:
                self._send(400, json.dumps({"error": f"bad request: {e}"}).encode(), "application/json")
                return
            status, payload = dispatch(svc, method, path, body)
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def log_message(self, *args):
            pass

    return Handler


def make_web_server(service: OptioService, host: str = "127.0.0.1",
                    port: int = 8788) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _handler_class(service))


def serve_web(argv: list[str] | None = None) -> None:
    """CLI entry point: serve the web UI over the real on-disk store (loopback)."""
    import argparse
    import webbrowser

    from optio import paths
    from optio.store import Store

    parser = argparse.ArgumentParser(prog="optio-web", description="Optio web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)

    service = OptioService(Store(paths.db_path()))
    server = make_web_server(service, host=args.host, port=args.port)
    url = f"http://{args.host}:{args.port}"
    print(f"optio web UI on {url}  (ctrl-c to stop)")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
