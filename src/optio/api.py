"""The JSON route table over OptioService — the automation surface.

Zero extra dependencies (stdlib ``http.server``). JSON in, JSON out. These
routes back both the web UI (``optio.web`` serves the SPA over them) and any
script or CI client. Routes:

    GET  /health
    POST /ingest                       {url, method?, target?, req_headers?, req_body?,
                                        status?, resp_headers?, resp_body?, elapsed_ms?}
                                        -> ingest forwarded traffic (e.g. live from Burp)
    GET  /targets                      list targets
    POST /targets                      {name, tech?, notes?, proxy?}
    GET  /targets/{name}               one target
    GET  /targets/{name}/config        per-target headers / User-Agent
    POST /targets/{name}/config        {config} | {headers?, user_agent?}
    GET  /targets/{name}/coverage      ran vs open tools
    GET  /targets/{name}/coverage-classes  what-to-find board (by vuln class)
    POST /targets/{name}/coverage-classes  {vuln_class, status, note?}
    GET  /targets/{name}/next          ranked next actions (auto Haruspex)
    GET  /targets/{name}/surface       attack-surface graph {nodes, edges}
    GET  /targets/{name}/assets        surface assets
    POST /targets/{name}/assets        {kind, value, parent_id?, data?}
    GET  /targets/{name}/findings      findings
    POST /targets/{name}/findings      {title, vuln_class?, endpoint?, severity?,
                                        status?, impact?, remediation?, cwe?, cvss?,
                                        reproduction?, evidence_request_id?}
    POST /targets/{name}/findings/{id}/status  {status}  -> confirm/promote a finding
    POST /targets/{name}/request       {method, url, headers?, body?, proxy?, verify?}
    POST /targets/{name}/request-raw   {raw, scheme?, proxy?, verify?}  -> send a raw request
    GET  /targets/{name}/requests      captured requests (durable evidence)
    GET  /targets/{name}/requests/{id} one captured request/response
    GET  /targets/{name}/report        {markdown} client report (confirmed findings)
    POST /targets/{name}/preview-command  {tool}  -> the exact command, editable before run
    POST /targets/{name}/run           {tool, command?, proxy?}  -> runs a tool (blocking)
    POST /targets/{name}/run-async     {tool, command?, proxy?}  -> starts a tool, returns {job_id}
    POST /targets/{name}/run-pipeline  {pipeline}                -> runs a chain (blocking)
    POST /targets/{name}/run-pipeline-async {pipeline}           -> starts a chain, returns {job_id}
    POST /targets/{name}/auto-run      {max_steps?, phases?}     -> smart early flow
    GET  /jobs/{id}                    async run status {status, elapsed_ms, results, ...}
    POST /jobs/{id}/cancel             cancel a running job (kills the process group)
    GET  /catalog                      catalog tools
    GET  /pipelines                    pipelines

Embed with ``make_server(service)`` (JSON only) or run ``optio`` for the full
web UI, which serves these same routes.
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
    # /targets/{name}/requests/{id}
    rq = re.fullmatch(r"/targets/([^/]+)/requests/(\d+)", path)
    if rq and method == "GET":
        one = svc.get_request(int(rq.group(2)))
        if one is None:
            raise _NotFound(f"no request {rq.group(2)}")
        return one
    # /targets/{name}/findings/{id}/status  -> confirm/promote a finding
    fs = re.fullmatch(r"/targets/([^/]+)/findings/(\d+)/status", path)
    if fs and method == "POST":
        if not body.get("status"):
            raise _BadRequest("status is required")
        return svc.set_finding_status(int(fs.group(2)), body["status"])
    # /jobs/{id}  (GET status) and /jobs/{id}/cancel (POST) -> async runs
    jc = re.fullmatch(r"/jobs/([0-9a-f]+)/cancel", path)
    if jc and method == "POST":
        res = svc.cancel_job(jc.group(1))
        if res is None:
            raise _NotFound(f"no job {jc.group(1)}")
        return res
    jb = re.fullmatch(r"/jobs/([0-9a-f]+)", path)
    if jb and method == "GET":
        res = svc.job_status(jb.group(1))
        if res is None:
            raise _NotFound(f"no job {jb.group(1)}")
        return res
    # /targets/{name}/...
    m = re.fullmatch(r"/targets/([^/]+)(?:/(\w[\w-]*))?", path)
    if path == "/health":
        return {"ok": True}
    if path == "/ingest" and method == "POST":
        # Live traffic forwarded from an intercepting proxy (e.g. a Burp
        # extension). Associates to a target by host and seeds the surface.
        return svc.ingest_request(body)
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
                                       status=body.get("status", "suspected"),
                                       notes=body.get("notes", ""),
                                       impact=body.get("impact", ""),
                                       remediation=body.get("remediation", ""),
                                       cwe=body.get("cwe", ""),
                                       cvss=body.get("cvss", ""),
                                       reproduction=body.get("reproduction", ""),
                                       evidence_request_id=body.get("evidence_request_id"))
            return svc.findings(name)
        if sub == "requests":
            return svc.requests(name)
        if sub == "config":
            if method == "POST":
                cfg = body.get("config")
                if cfg is None:
                    cfg = {k: body[k] for k in ("headers", "user_agent") if k in body}
                return svc.set_config(name, cfg)
            return svc.get_config(name)
        if sub == "surface":
            return svc.surface_graph(name)
        if sub == "assets":
            if method == "POST":
                if not body.get("value"):
                    raise _BadRequest("value is required")
                return svc.record_asset(name, body.get("kind", "endpoint"), body["value"],
                                        parent_id=body.get("parent_id"), data=body.get("data"))
            return svc.list_assets(name)
        if sub == "coverage-classes":
            if method == "POST":
                if not body.get("vuln_class"):
                    raise _BadRequest("vuln_class is required")
                return svc.record_class_coverage(name, body["vuln_class"],
                                                 body.get("status", "tested"),
                                                 note=body.get("note", ""))
            return svc.coverage_board(name)
        if sub == "report":
            return {"markdown": svc.report(name, audience=body.get("audience", "client")
                                           if method == "POST" else "client")}
        if sub == "request" and method == "POST":
            if not body.get("url"):
                raise _BadRequest("url is required")
            return svc.send_request(name, body.get("method", "GET"), body["url"],
                                    headers=body.get("headers"), body=body.get("body", ""),
                                    proxy=body.get("proxy"), verify=body.get("verify"))
        if sub == "request-raw" and method == "POST":
            if not body.get("raw"):
                raise _BadRequest("raw is required")
            return svc.send_raw(name, body["raw"], scheme=body.get("scheme", "https"),
                                proxy=body.get("proxy"), verify=body.get("verify"))
        if sub == "preview-command" and method == "POST":
            if not body.get("tool"):
                raise _BadRequest("tool is required")
            return svc.preview_command(name, body["tool"])
        if sub == "run" and method == "POST":
            if not body.get("tool"):
                raise _BadRequest("tool is required")
            return svc.run_tool(name, body["tool"], command=body.get("command"),
                                proxy=body.get("proxy"))
        if sub == "run-async" and method == "POST":
            if not body.get("tool"):
                raise _BadRequest("tool is required")
            return svc.run_tool_async(name, body["tool"], command=body.get("command"),
                                      proxy=body.get("proxy"))
        if sub == "run-pipeline" and method == "POST":
            if not body.get("pipeline"):
                raise _BadRequest("pipeline is required")
            return svc.run_pipeline(name, body["pipeline"])
        if sub == "run-pipeline-async" and method == "POST":
            if not body.get("pipeline"):
                raise _BadRequest("pipeline is required")
            return svc.run_pipeline_async(name, body["pipeline"])
        if sub in ("auto-run", "auto-run-async") and method == "POST":
            kw = {}
            if body.get("max_steps"):
                kw["max_steps"] = int(body["max_steps"])
            if body.get("phases"):
                kw["phases"] = tuple(body["phases"])
            if sub == "auto-run-async":
                return svc.auto_run_async(name, **kw)
            return svc.auto_run(name, **kw)
    raise _NotFound(f"no route {method} {path}")


def dispatch(svc: OptioService, method: str, path: str, body: dict) -> tuple[int, object]:
    """Run a route and map exceptions to (status, payload). Shared by the JSON
    API handler and the web UI server so both behave identically."""
    try:
        return 200, _route(svc, method, path, body)
    except _NotFound as e:
        return 404, {"error": str(e)}
    except _BadRequest as e:
        return 400, {"error": str(e)}
    except (ValueError, KeyError) as e:
        return 400, {"error": f"bad request: {e}"}
    except Exception as e:  # never leak a stack trace to the client
        return 500, {"error": f"internal error: {e}"}


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
            except (ValueError, KeyError) as e:
                self._send(400, {"error": f"bad request: {e}"})
                return
            status, payload = dispatch(svc, method, self.path.split("?", 1)[0], body)
            self._send(status, payload)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def log_message(self, *args):
            pass  # quiet by default

    return Handler


def make_server(service: OptioService, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    """Build the JSON-only API server. The web UI (``optio.web``) wraps the same
    routes and serves the SPA alongside them; this bare server is for embedding
    and tests."""
    return ThreadingHTTPServer((host, port), _handler_class(service))
