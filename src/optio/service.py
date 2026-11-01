"""OptioService — the programmatic facade over the engine.

This is the API automation drives: the same store, catalog, advisor, and
pipelines the TUI uses, with no terminal and no external engine. Build one with a
Store (and optionally a runner to inject for tests), then call its methods or put
the HTTP layer (``optio.api``) in front of it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict

from optio import paths
from optio.advisor import suggest
from optio.catalog import Tool, load_catalog, load_default_catalog
from optio.context import target_values
from optio.executor import RunResult
from optio.executor import run as _run
from optio.flow import phase_rank
from optio.pipeline import build_command, load_default_pipelines, load_pipelines, run_pipeline
from optio.store import Store
from optio.summarize import summarize

Runner = Callable[..., RunResult]


class OptioService:
    def __init__(self, store: Store, catalog: list[Tool] | None = None,
                 pipelines: list | None = None, runner: Runner = _run):
        self.store = store
        self.runner = runner
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
        return [asdict(s) for s in suggest(
            self.catalog, tech, self.store.tools_run_for_target(name),
            self.store.findings_for_target(name), target_values(name))]

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

    # ── findings ────────────────────────────────────────────────────────────
    def findings(self, name: str) -> list[dict]:
        return self.store.findings_for_target(name)

    def add_finding(self, name: str, **kw) -> dict:
        fid = self.store.add_finding(name, **kw)
        return {"id": fid, **kw}
