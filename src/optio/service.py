"""OptioService — the programmatic facade over the engine.

This is the API automation drives: the same store, catalog, advisor, and
pipelines the TUI uses, with no terminal and no external engine. Build one with a
Store (and optionally a runner to inject for tests), then call its methods or put
the HTTP layer (``optio.api``) in front of it.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from optio import haruspex, http, paths, report
from optio.advisor import class_coverage, rerank, suggest
from optio.catalog import Tool, load_catalog, load_default_catalog
from optio.context import target_values
from optio.executor import RunResult
from optio.executor import run as _run
from optio.flow import phase_rank
from optio.pipeline import build_command, load_default_pipelines, load_pipelines, run_pipeline
from optio.runs import JobManager
from optio.store import Store
from optio.summarize import summarize

Runner = Callable[..., RunResult]
HttpSend = Callable[..., http.HttpResponse]
# (options, target, tech) -> options best-first, or None to abstain.
TargetRanker = Callable[[list[str], str, str], "list[str] | None"]

_RANK_QUESTION = "Which tool should the operator run next on this target?"
_SEV_ORDER = ["critical", "high", "medium", "low"]  # worst first, for graph node colour


def _haruspex_ranker(options: list[str], target: str, tech: str) -> list[str] | None:
    return haruspex.rank_candidates(_RANK_QUESTION, options, target=target, domain=tech)


def _endpoint_value(url: str) -> str:
    """``host/path`` (no scheme, no query) for a surface-graph endpoint node.
    A bare root path collapses to the host so '/' requests map to the host node."""
    s = urlsplit(url if "://" in url else "https://" + url)
    path = (s.path or "").rstrip("/")
    return f"{s.netloc}{path}" if path else s.netloc


class OptioService:
    def __init__(self, store: Store, catalog: list[Tool] | None = None,
                 pipelines: list | None = None, runner: Runner = _run,
                 http_send: HttpSend = http.send,
                 ranker: TargetRanker = _haruspex_ranker):
        self.store = store
        self.runner = runner
        self.http_send = http_send
        self.jobs = JobManager()   # background runs: non-blocking, pollable, cancellable
        # Haruspex rides the flow automatically (fail-open). Tests inject a
        # ranker that abstains to isolate the deterministic ladder.
        self.ranker = ranker
        if catalog is None:
            user = sorted(paths.user_catalog_dir().glob("*.yaml")) if paths.user_catalog_dir().exists() else []
            merged = {t.name: t for t in load_default_catalog() + load_catalog(user)}
            catalog = list(merged.values())
        self.catalog = catalog
        self._by_name = {t.name: t for t in self.catalog}
        if pipelines is None:
            pipelines = load_default_pipelines()
        self.pipelines = pipelines

    # ── targets ──────────────────────────────────────────────────────────
    def add_target(self, name: str, tech: list[str] | None = None, notes: str = "",
                   proxy: str = "", artifacts_dir: str = "") -> dict:
        self.store.add_target(name, tech=tech, notes=notes, proxy=proxy, artifacts_dir=artifacts_dir)
        return self.store.get_target(name)

    def list_targets(self) -> list[dict]:
        return self.store.list_targets()

    def get_target(self, name: str) -> dict | None:
        return self.store.get_target(name)

    def get_config(self, name: str) -> dict:
        t = self.store.get_target(name) or {}
        cfg = dict(t.get("config") or {})
        cfg["proxy"] = t.get("proxy") or ""        # proxy lives on the target row
        return cfg

    def set_config(self, name: str, config: dict) -> dict:
        """Per-target config. ``proxy`` is stored on the target row (so tools and
        the request runner both use it); the rest — ``headers``, ``user_agent``,
        ``verify_tls`` — lives in the config blob."""
        cfg = dict(config or {})
        proxy = cfg.pop("proxy", None)
        if proxy is not None:
            self.store.set_proxy(name, proxy)
        self.store.set_config(name, cfg)
        return self.get_config(name)

    # ── catalog / pipelines ───────────────────────────────────────────────
    def catalog_list(self) -> list[dict]:
        # `installed` lets the UI flag tools whose binary is not on PATH before
        # the operator runs one (and hits a 127). which() is cheap and cached.
        out = []
        for t in self.catalog:
            d = asdict(t)
            d["installed"] = shutil.which(t.binary) is not None
            out.append(d)
        return out

    def pipeline_list(self) -> list[dict]:
        return [asdict(p) for p in self.pipelines]

    def preview_command(self, name: str, tool: str) -> dict:
        """The exact command Optio would run for ``tool`` — flag memory if set,
        else the template partially filled from the target (unfilled ``{fields}``
        left literal). Lets the operator see and edit the line before it fires."""
        t = self._by_name.get(tool)
        if t is None:
            return {"error": f"unknown tool: {tool}"}
        tvals = target_values(name)
        remembered = self.store.get_flags(name, tool)
        command = remembered or t.render_partial(tvals)
        return {"tool": tool, "command": command,
                "remembered": bool(remembered),
                "missing": [] if remembered else t.missing_placeholders(tvals)}

    # ── coverage / advice ──────────────────────────────────────────────────
    def coverage(self, name: str) -> dict:
        ran = self.store.tools_run_for_target(name)
        host = [t for t in self.catalog if t.host_targetable()]
        return {
            "ran": sorted(ran),
            "open": sorted(t.name for t in host if t.name not in ran),
            "tools": [
                {"name": t.name, "lane": t.lane, "phase": t.phase, "scope": t.scope,
                 "ran": t.name in ran}
                for t in sorted(self.catalog, key=lambda x: (phase_rank(x.phase), x.name))
            ],
        }

    def next_actions(self, name: str) -> list[dict]:
        target = self.store.get_target(name) or {}
        tech = target.get("tech") or ["default"]
        sugs = suggest(
            self.catalog, tech, self.store.tools_run_for_target(name),
            self.store.findings_for_target(name), target_values(name))
        # Haruspex re-ranks the runnable steps automatically; abstains silently.
        sugs = rerank(sugs, lambda opts: self.ranker(opts, name, ",".join(tech)))
        return [asdict(s) for s in sugs]

    # ── execution ───────────────────────────────────────────────────────────
    def _run_cwd(self, name: str) -> str:
        """Working directory for a target's tool subprocesses: the target's
        configured ``artifacts_dir`` if set, else a per-target dir under the
        data home. Keeps tool-written reports out of the operator's CWD/repo."""
        configured = ((self.store.get_target(name) or {}).get("artifacts_dir") or "").strip()
        if configured:
            Path(configured).mkdir(parents=True, exist_ok=True)
            return configured
        return str(paths.artifacts_dir(name))

    def run_tool(self, name: str, tool: str, command: str | None = None,
                 proxy: str | None = None) -> dict:
        t = self._by_name.get(tool)
        if t is None:
            return {"error": f"unknown tool: {tool}"}
        tvals = target_values(name)
        if not command:
            command, reason = build_command(t, tvals, lambda n: self.store.get_flags(name, n))
            if command is None:
                return {"error": reason, "tool": tool}
        proxy = proxy or (self.store.get_target(name) or {}).get("proxy") or None
        result = self.runner(command, proxy, cwd=self._run_cwd(name))
        summary = summarize(tool, result.exit_code, result.output)
        self.store.record_run(name, tool, command, result.exit_code, summary)
        self.store.save_flags(name, tool, command)
        return {"tool": tool, "command": command, "exit_code": result.exit_code,
                "summary": summary, "output": result.output}

    def run_pipeline(self, name: str, pipeline: str) -> list[dict]:
        pipe = next((p for p in self.pipelines if p.name == pipeline), None)
        if pipe is None:
            return [{"error": f"unknown pipeline: {pipeline}"}]
        tvals = target_values(name)
        proxy = (self.store.get_target(name) or {}).get("proxy") or None
        cwd = self._run_cwd(name)
        results = run_pipeline(
            pipe, self._by_name, tvals,
            flag_lookup=lambda n: self.store.get_flags(name, n),
            runner=lambda c: self.runner(c, proxy, cwd=cwd),
            recorder=lambda tl, cmd, code, summ: self.store.record_run(name, tl, cmd, code, summ),
        )
        return [asdict(r) for r in results]

    # ── async runs (non-blocking, pollable, cancellable) ──────────────────────
    def run_tool_async(self, name: str, tool: str, command: str | None = None,
                       proxy: str | None = None) -> dict:
        """Start a tool run in the background and return a job id at once. The UI
        polls ``job_status`` for progress and can ``cancel_job`` it. Records the
        result exactly like the synchronous ``run_tool`` when it finishes."""
        t = self._by_name.get(tool)
        if t is None:
            return {"error": f"unknown tool: {tool}"}
        tvals = target_values(name)
        if not command:
            command, reason = build_command(t, tvals, lambda n: self.store.get_flags(name, n))
            if command is None:
                return {"error": reason, "tool": tool}
        proxy = proxy or (self.store.get_target(name) or {}).get("proxy") or None
        cwd = self._run_cwd(name)

        def work(job):
            result = self.runner(command, proxy, cwd=cwd, on_start=job.set_proc)
            summary = summarize(tool, result.exit_code, result.output)
            self.store.record_run(name, tool, command, result.exit_code, summary)
            self.store.save_flags(name, tool, command)
            job.results.append({"tool": tool, "command": command,
                                "exit_code": result.exit_code, "summary": summary})

        job = self.jobs.submit("tool", tool, work)
        return {"job_id": job.id, "tool": tool, "command": command}

    def run_pipeline_async(self, name: str, pipeline: str) -> dict:
        pipe = next((p for p in self.pipelines if p.name == pipeline), None)
        if pipe is None:
            return {"error": f"unknown pipeline: {pipeline}"}
        tvals = target_values(name)
        proxy = (self.store.get_target(name) or {}).get("proxy") or None
        cwd = self._run_cwd(name)

        def work(job):
            results = run_pipeline(
                pipe, self._by_name, tvals,
                flag_lookup=lambda n: self.store.get_flags(name, n),
                runner=lambda c: self.runner(c, proxy, cwd=cwd, on_start=job.set_proc),
                recorder=lambda tl, cmd, code, summ: self.store.record_run(name, tl, cmd, code, summ),
                cancelled=job.cancelled,
            )
            job.results.extend(asdict(r) for r in results)

        job = self.jobs.submit("pipeline", pipeline, work)
        return {"job_id": job.id, "pipeline": pipeline}

    def job_status(self, job_id: str) -> dict | None:
        return self.jobs.get(job_id)

    def cancel_job(self, job_id: str) -> dict | None:
        return self.jobs.cancel(job_id)

    # ── request runner (standalone repeater) ─────────────────────────────────
    def send_request(self, name: str, method: str, url: str,
                     headers: dict | None = None, body: str = "",
                     proxy: str | None = None, verify: bool | None = None) -> dict:
        target = self.store.get_target(name) or {}
        proxy = proxy or target.get("proxy") or None
        # Merge per-target config: default headers + User-Agent. Caller wins.
        cfg = target.get("config") or {}
        # TLS verification: explicit arg wins, else the target's configured
        # default, else on. Routing through Burp usually means verify_tls:false.
        if verify is None:
            verify = cfg.get("verify_tls", True)
        merged = dict(cfg.get("headers") or {})
        if cfg.get("user_agent"):
            merged.setdefault("User-Agent", cfg["user_agent"])
        merged.update(headers or {})
        headers = merged
        resp = self.http_send(method, url, headers=headers, body=body, proxy=proxy, verify=verify)
        rid = self.store.record_request(
            name, method=method, url=url, req_headers=headers or {}, req_body=body or "",
            status=resp.status, resp_headers=dict(resp.headers), resp_body=resp.body,
            elapsed_ms=resp.elapsed_ms)
        return {"request_id": rid, "status": resp.status, "elapsed_ms": resp.elapsed_ms,
                "resp_headers": resp.headers, "resp_preview": resp.body[:2000],
                "error": resp.error}

    def send_raw(self, name: str, raw: str, scheme: str = "https",
                 proxy: str | None = None, verify: bool | None = None) -> dict:
        try:
            method, url, headers, body = http.parse_raw(raw, scheme=scheme)
        except ValueError as e:
            return {"error": str(e)}
        return self.send_request(name, method, url, headers=headers, body=body,
                                 proxy=proxy, verify=verify)

    def requests(self, name: str, limit: int = 50) -> list[dict]:
        return self.store.requests_for_target(name, limit=limit)

    def get_request(self, request_id: int) -> dict | None:
        return self.store.get_request(request_id)

    def ingest_request(self, payload: dict) -> dict:
        """Ingest one request/response captured elsewhere — e.g. forwarded live
        from Burp. Associates it with a target (the caller's ``target``, else the
        URL host, auto-creating it), records it as a captured request, and seeds
        the surface graph with the host + endpoint. Fail-soft: a malformed item
        returns an error rather than raising, so a noisy feed never crashes."""
        url = (payload.get("url") or "").strip()
        if not url:
            return {"error": "url is required"}
        name = (payload.get("target") or "").strip() or target_values(url)["host"]
        if not name:
            return {"error": "could not determine a target from the request"}
        if self.store.get_target(name) is None:
            self.store.add_target(name)
        rid = self.store.record_request(
            name, method=payload.get("method", "GET"), url=url,
            req_headers=payload.get("req_headers") or {}, req_body=payload.get("req_body", ""),
            status=int(payload.get("status") or 0),
            resp_headers=payload.get("resp_headers") or {}, resp_body=payload.get("resp_body", ""),
            elapsed_ms=int(payload.get("elapsed_ms") or 0))
        host = target_values(url)["host"]
        host_id = self.store.add_asset(name, "host", host)
        endpoint = _endpoint_value(url)
        if endpoint and endpoint != host:
            self.store.add_asset(name, "endpoint", endpoint, parent_id=host_id)
        return {"request_id": rid, "target": name}

    # ── findings ────────────────────────────────────────────────────────────
    def findings(self, name: str) -> list[dict]:
        return self.store.findings_for_target(name)

    def add_finding(self, name: str, **kw) -> dict:
        fid = self.store.add_finding(name, **kw)
        return {"id": fid, **kw}

    def set_finding_status(self, finding_id: int, status: str) -> dict:
        """Promote/demote a finding (e.g. ``suspected`` -> ``confirmed``). Only
        confirmed findings reach the client report, so this is the gate between
        bookkeeping and the deliverable."""
        self.store.set_finding_status(finding_id, status)
        return {"id": finding_id, "status": status}

    # ── attack surface (the graph) ───────────────────────────────────────────
    def record_asset(self, name: str, kind: str, value: str,
                     parent_id: int | None = None, data: dict | None = None) -> dict:
        aid = self.store.add_asset(name, kind, value, parent_id=parent_id, data=data)
        return {"id": aid, "kind": kind, "value": value, "parent_id": parent_id}

    def list_assets(self, name: str) -> list[dict]:
        return self.store.assets_for_target(name)

    def surface_graph(self, name: str) -> dict:
        """Nodes + edges for the web UI. Each node inherits the worst severity
        of the findings on its endpoint, so the graph lights up where risk is."""
        assets = self.store.assets_for_target(name)
        findings = self.store.findings_for_target(name)
        # worst severity + count per endpoint value
        by_ep: dict[str, list[dict]] = {}
        for f in findings:
            by_ep.setdefault(f.get("endpoint") or "", []).append(f)
        nodes, edges = [], []
        for a in assets:
            fs = by_ep.get(a["value"], [])
            sev = min((f["severity"] for f in fs),
                      key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 99, default="")
            nodes.append({"id": a["id"], "kind": a["kind"], "value": a["value"],
                          "data": a["data"], "severity": sev, "finding_count": len(fs)})
            if a["parent_id"] is not None:
                edges.append({"source": a["parent_id"], "target": a["id"]})
        return {"nodes": nodes, "edges": edges}

    # ── smart auto-run ────────────────────────────────────────────────────────
    def auto_run(self, name: str, max_steps: int = 25,
                 phases: tuple[str, ...] = ("recon", "surface", "scan"),
                 on_start=None, cancelled=lambda: False) -> dict:
        """Run the early flow unattended, in the advisor's value order, to save
        time. Walks ``phases`` (recon -> surface -> scan by default), runs each
        tool whose command can be filled from the target, and stops before the
        probe phase. A tool with an unfilled placeholder is skipped, not retried.

        ``on_start``/``cancelled`` let the async wrapper register each subprocess
        and stop the walk between steps when the operator cancels.
        """
        target = self.store.get_target(name) or {}
        tech = target.get("tech") or ["default"]
        tvals = target_values(name)
        proxy = target.get("proxy") or None
        findings = self.store.findings_for_target(name)
        virtual_run = set(self.store.tools_run_for_target(name))
        steps: list[dict] = []
        for _ in range(max_steps):
            if cancelled():
                break
            sugs = suggest(self.catalog, tech, virtual_run, findings, tvals, max_suggestions=50)
            nxt = next((s for s in sugs if s.tool and s.phase in phases), None)
            if nxt is None:
                break
            tool = self._by_name[nxt.tool]
            command, reason = build_command(tool, tvals, lambda n: self.store.get_flags(name, n))
            if command is None:  # e.g. needs a {wordlist} — skip, don't loop
                virtual_run.add(nxt.tool)
                steps.append({"tool": nxt.tool, "skipped": reason})
                continue
            result = self.runner(command, proxy, cwd=self._run_cwd(name), on_start=on_start)
            summary = summarize(nxt.tool, result.exit_code, result.output)
            self.store.record_run(name, nxt.tool, command, result.exit_code, summary)
            self.store.save_flags(name, nxt.tool, command)
            virtual_run.add(nxt.tool)
            steps.append({"tool": nxt.tool, "command": command,
                          "exit_code": result.exit_code, "summary": summary})
        return {"steps": steps}

    def auto_run_async(self, name: str, max_steps: int = 25,
                       phases: tuple[str, ...] = ("recon", "surface", "scan")) -> dict:
        def work(job):
            out = self.auto_run(name, max_steps=max_steps, phases=phases,
                                on_start=job.set_proc, cancelled=job.cancelled)
            job.results.extend(out["steps"])
        job = self.jobs.submit("auto-run", "auto-run", work)
        return {"job_id": job.id}

    # ── coverage by vuln class ───────────────────────────────────────────────
    def coverage_board(self, name: str) -> list[dict]:
        """Every applicable vuln class with its tested/untested status — the
        completeness view that does not depend on a tool existing."""
        target = self.store.get_target(name) or {}
        tech = target.get("tech") or ["default"]
        return class_coverage(tech, self.store.class_coverage_map(name))

    def record_class_coverage(self, name: str, vuln_class: str, status: str,
                              note: str = "") -> dict:
        self.store.record_coverage(name, vuln_class, status, note=note)
        return {"vuln_class": vuln_class, "status": status}

    # ── report ────────────────────────────────────────────────────────────────
    def report(self, name: str, audience: str = "client") -> str:
        return report.render_markdown(
            name, self.store.findings_for_target(name), audience=audience,
            request_lookup=self.store.get_request)
