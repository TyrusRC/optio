"""OptioService — the programmatic facade over the engine.

This is the API automation drives: the same store, catalog, advisor, and
pipelines the TUI uses, with no terminal and no external engine. Build one with a
Store (and optionally a runner to inject for tests), then call its methods or put
the HTTP layer (``optio.api``) in front of it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict

from optio import haruspex, http, paths, report
from optio.advisor import class_coverage, rerank, suggest
from optio.catalog import Tool, load_catalog, load_default_catalog
from optio.context import target_values
from optio.executor import RunResult
from optio.executor import run as _run
from optio.flow import phase_rank
from optio.pipeline import build_command, load_default_pipelines, load_pipelines, run_pipeline
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


class OptioService:
    def __init__(self, store: Store, catalog: list[Tool] | None = None,
                 pipelines: list | None = None, runner: Runner = _run,
                 http_send: HttpSend = http.send,
                 ranker: TargetRanker = _haruspex_ranker):
        self.store = store
        self.runner = runner
        self.http_send = http_send
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
        return (self.store.get_target(name) or {}).get("config") or {}

    def set_config(self, name: str, config: dict) -> dict:
        self.store.set_config(name, config)
        return config

    # ── catalog / pipelines ───────────────────────────────────────────────
    def catalog_list(self) -> list[dict]:
        return [asdict(t) for t in self.catalog]

    def pipeline_list(self) -> list[dict]:
        return [asdict(p) for p in self.pipelines]

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
        result = self.runner(command, proxy)
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
        results = run_pipeline(
            pipe, self._by_name, tvals,
            flag_lookup=lambda n: self.store.get_flags(name, n),
            runner=lambda c: self.runner(c, proxy),
            recorder=lambda tl, cmd, code, summ: self.store.record_run(name, tl, cmd, code, summ),
        )
        return [asdict(r) for r in results]

    # ── request runner (standalone repeater) ─────────────────────────────────
    def send_request(self, name: str, method: str, url: str,
                     headers: dict | None = None, body: str = "",
                     proxy: str | None = None, verify: bool = True) -> dict:
        target = self.store.get_target(name) or {}
        proxy = proxy or target.get("proxy") or None
        # Merge per-target config: default headers + User-Agent. Caller wins.
        cfg = target.get("config") or {}
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
                 proxy: str | None = None, verify: bool = True) -> dict:
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

    # ── findings ────────────────────────────────────────────────────────────
    def findings(self, name: str) -> list[dict]:
        return self.store.findings_for_target(name)

    def add_finding(self, name: str, **kw) -> dict:
        fid = self.store.add_finding(name, **kw)
        return {"id": fid, **kw}

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
                 phases: tuple[str, ...] = ("recon", "surface", "scan")) -> dict:
        """Run the early flow unattended, in the advisor's value order, to save
        time. Walks ``phases`` (recon -> surface -> scan by default), runs each
        tool whose command can be filled from the target, and stops before the
        probe phase. A tool with an unfilled placeholder is skipped, not retried.
        """
        target = self.store.get_target(name) or {}
        tech = target.get("tech") or ["default"]
        tvals = target_values(name)
        proxy = target.get("proxy") or None
        findings = self.store.findings_for_target(name)
        virtual_run = set(self.store.tools_run_for_target(name))
        steps: list[dict] = []
        for _ in range(max_steps):
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
            result = self.runner(command, proxy)
            summary = summarize(nxt.tool, result.exit_code, result.output)
            self.store.record_run(name, nxt.tool, command, result.exit_code, summary)
            self.store.save_flags(name, nxt.tool, command)
            virtual_run.add(nxt.tool)
            steps.append({"tool": nxt.tool, "command": command,
                          "exit_code": result.exit_code, "summary": summary})
        return {"steps": steps}

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
