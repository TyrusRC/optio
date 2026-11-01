"""A small HTTP API over OptioService — the automation surface.

Zero extra dependencies (stdlib ``http.server``). JSON in, JSON out. Drive Optio
from scripts, CI, or any HTTP client without the TUI and without any external
engine. Routes:

    GET  /health
    GET  /targets                      list targets
    POST /targets                      {name, tech?, notes?, proxy?}
    GET  /targets/{name}               one target
    GET  /targets/{name}/coverage      ran vs open tools
    GET  /targets/{name}/next          ranked next actions
    GET  /targets/{name}/findings      findings
    POST /targets/{name}/findings      {title, vuln_class?, endpoint?, severity?}
    POST /targets/{name}/run           {tool, command?, proxy?}  -> runs a tool
    POST /targets/{name}/run-pipeline  {pipeline}                -> runs a chain
    GET  /catalog                      catalog tools
    GET  /pipelines                    pipelines

Run it: ``optio-api`` (the ``serve`` entry point) or ``make_server(service).serve_forever()``.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from optio.service import OptioService


class _NotFound(Exception):
    pass


class _BadRequest(Exception):
    pass


def _route(svc: OptioService, method: str, path: str, body: dict):
    # /targets/{name}/...
    m = re.fullmatch(r"/targets/([^/]+)(?:/(\w[\w-]*))?", path)
    if path == "/health":
        return {"ok": True}
    if path == "/catalog":
        return svc.catalog_list()
    if path == "/pipelines":
        return svc.pipeline_list()
    if path == "/targets":
        if method == "GET":
            return svc.list_targets()
        if method == "POST":
            if not body.get("name"):
                raise _BadRequest("name is required")
            return svc.add_target(body["name"], tech=body.get("tech"),
                                  notes=body.get("notes", ""), proxy=body.get("proxy", ""))
        raise _BadRequest("method not allowed")
    if m:
        name = unquote(m.group(1))
        sub = m.group(2)
        if sub is None:
            t = svc.get_target(name)
            if t is None:
                raise _NotFound(f"no target {name}")
            return t
        if sub == "coverage":
            return svc.coverage(name)
        if sub == "next":
            return svc.next_actions(name)
        if sub == "findings":
            if method == "POST":
                if not body.get("title"):
                    raise _BadRequest("title is required")
                return svc.add_finding(name, title=body["title"],
                                       vuln_class=body.get("vuln_class", ""),
                                       endpoint=body.get("endpoint", ""),
                                       severity=body.get("severity", "low"),
                                       notes=body.get("notes", ""))
            return svc.findings(name)
        if sub == "run" and method == "POST":
            if not body.get("tool"):
                raise _BadRequest("tool is required")
            return svc.run_tool(name, body["tool"], command=body.get("command"),
                                proxy=body.get("proxy"))
        if sub == "run-pipeline" and method == "POST":
            if not body.get("pipeline"):
                raise _BadRequest("pipeline is required")
            return svc.run_pipeline(name, body["pipeline"])
    raise _NotFound(f"no route {method} {path}")


def _handler_class(svc: OptioService):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, payload):
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _dispatch(self, method: str):
            try:
                body = {}
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
                result = _route(svc, method, self.path.split("?", 1)[0], body)
                self._send(200, result)
            except _NotFound as e:
                self._send(404, {"error": str(e)})
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except (ValueError, KeyError) as e:
                self._send(400, {"error": f"bad request: {e}"})
            except Exception as e:  # never leak a stack trace to the client
                self._send(500, {"error": f"internal error: {e}"})

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def log_message(self, *args):
            pass  # quiet by default

    return Handler


def make_server(service: OptioService, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _handler_class(service))


def serve(argv: list[str] | None = None) -> None:
    """CLI entry point: start the API over the real on-disk store.

    Bind defaults to loopback — the API runs tools and reads findings, so it
    stays local unless the operator opts out explicitly.
    """
    import argparse

    from optio import paths
    from optio.store import Store

    parser = argparse.ArgumentParser(prog="optio-api", description="Optio automation API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)

    service = OptioService(Store(paths.db_path()))
    server = make_server(service, host=args.host, port=args.port)
    print(f"optio-api on http://{args.host}:{args.port}  (ctrl-c to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
