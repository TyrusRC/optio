"""The Optio cockpit — targets, a coverage board, and the next-action advisor.

One target in focus. The left pane lists targets; the right pane shows the
coverage grid (which catalog tools ran vs. are open), the ranked next actions,
and a quiet activity log. The operator decides every run; Optio pre-fills the
command and records what ran.
"""

from __future__ import annotations

import asyncio

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, ListItem, ListView, Label, Static

from optio import haruspex, paths
from optio.advisor import Suggestion, suggest
from optio.catalog import Tool, load_catalog, load_default_catalog
from optio.context import target_values
from optio.executor import run as run_tool
from optio.flow import phase_rank
from optio.pipeline import build_command, load_default_pipelines, load_pipelines
from optio.store import Store
from optio.summarize import summarize
from optio.tui.modals import PromptModal


class OptioApp(App):
    CSS = """
    #targets { width: 32; border: round $primary; }
    #detail { border: round $primary; }
    #coverage { height: 1fr; }
    #nextaction { height: auto; padding: 1; border-top: solid $secondary; }
    #log { height: 8; padding: 1; border-top: solid $secondary; color: $text-muted; }
    #prompt-box { width: 80; height: auto; padding: 1 2; border: thick $primary; background: $surface; }
    #prompt-title { text-style: bold; }
    #prompt-note { color: $text-muted; }
    """

    BINDINGS = [
        ("a", "add_target", "Add target"),
        ("r", "run_suggested", "Run next action"),
        ("p", "run_pipeline", "Run pipeline"),
        ("h", "haruspex_hint", "Haruspex rank"),
        ("f", "full_output", "Full output"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, store: Store | None = None) -> None:
        super().__init__()
        self.store = store or Store(paths.db_path())
        self.catalog: list[Tool] = load_default_catalog() + load_catalog(
            sorted(paths.user_catalog_dir().glob("*.yaml")) if paths.user_catalog_dir().exists() else []
        )
        # dedupe by name, user entries win
        seen: dict[str, Tool] = {}
        for t in self.catalog:
            seen[t.name] = t
        self.catalog = list(seen.values())
        self.pipelines = load_default_pipelines() + load_pipelines(
            sorted(paths.user_catalog_dir().glob("*pipeline*.yaml")) if paths.user_catalog_dir().exists() else []
        )
        self._targets: list[str] = []
        self._suggestions: list[Suggestion] = []
        self._last_output: str = ""
        self._log_lines: list[str] = []

    # ── layout ────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            yield ListView(id="targets")
            with Vertical(id="detail"):
                yield DataTable(id="coverage")
                yield Static("", id="nextaction")
                yield Static("", id="log")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Optio"
        self.sub_title = "operator cockpit"
        dt = self.query_one("#coverage", DataTable)
        dt.add_columns("", "Tool", "Lane", "Phase")
        dt.cursor_type = "none"
        self.refresh_targets()

    # ── data refresh ────────────────────────────────────────────────────────
    def refresh_targets(self) -> None:
        lv = self.query_one("#targets", ListView)
        lv.clear()
        self._targets = [t["name"] for t in self.store.list_targets()]
        for name in self._targets:
            lv.append(ListItem(Label(name)))
        if self._targets:
            lv.index = min(lv.index or 0, len(self._targets) - 1)
            self.refresh_detail()
        else:
            self.query_one("#nextaction", Static).update(
                "No targets yet. Press [b]a[/b] to add one."
            )

    def _current_target(self) -> str | None:
        lv = self.query_one("#targets", ListView)
        if lv.index is None or not self._targets:
            return None
        return self._targets[lv.index]

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.id == "targets":
            self.refresh_detail()

    def refresh_detail(self) -> None:
        name = self._current_target()
        if not name:
            return
        target = self.store.get_target(name) or {}
        tech = target.get("tech") or ["default"]
        tools_run = self.store.tools_run_for_target(name)
        findings = self.store.findings_for_target(name)
        tvals = target_values(name)

        # coverage grid
        dt = self.query_one("#coverage", DataTable)
        dt.clear()
        for t in sorted(self.catalog, key=lambda x: (phase_rank(x.phase), x.name)):
            mark = "[green]✓[/green]" if t.name in tools_run else "[dim]·[/dim]"
            dt.add_row(mark, t.name, t.lane, t.phase)

        # next action
        self._suggestions = suggest(self.catalog, tech, tools_run, findings, tvals)
        self.query_one("#nextaction", Static).update(self._format_suggestions(findings))

    def _format_suggestions(self, findings: list[dict]) -> str:
        head = f"[b]Next action[/b]  ·  {len(findings)} finding(s)\n"
        if not self._suggestions:
            return head + "[dim]nothing suggested[/dim]"
        lines = [head]
        for i, s in enumerate(self._suggestions):
            marker = "[b yellow]▶[/b yellow]" if i == 0 else " "
            lines.append(f"{marker} {s.action}")
            lines.append(f"   [dim]{s.reason}[/dim]")
            if s.command:
                lines.append(f"   [cyan]$ {s.command}[/cyan]")
        return "\n".join(lines)

    def _top_runnable(self) -> Suggestion | None:
        for s in self._suggestions:
            if s.tool:
                return s
        return None

    # ── actions ───────────────────────────────────────────────────────────
    @work
    async def action_add_target(self) -> None:
        name = await self.push_screen_wait(
            PromptModal("Add target (host or URL)", note="e.g. example.com"))
        if name and name.strip():
            self.store.add_target(name.strip())
            self.refresh_targets()
            self.notify(f"Added {name.strip()}")

    @work
    async def action_run_suggested(self) -> None:
        name = self._current_target()
        if not name:
            self.notify("Add and select a target first.", severity="warning")
            return
        s = self._top_runnable()
        if not s or not s.tool:
            self.notify("Top action is manual — no tool to run.", severity="warning")
            return
        tool = next((t for t in self.catalog if t.name == s.tool), None)
        if not tool:
            return
        tvals = target_values(name)
        initial = self.store.get_flags(name, tool.name) or tool.render_partial(tvals)
        command = await self.push_screen_wait(PromptModal(
            f"Run {tool.name}", initial=initial, confirm_label="Run",
            note="Review and edit the command. It runs on confirm."))
        if not command or not command.strip():
            return
        command = command.strip()
        proxy = (self.store.get_target(name) or {}).get("proxy") or None
        self.notify(f"Running {tool.name}…")
        result = await asyncio.to_thread(run_tool, command, proxy)
        summary = summarize(tool.name, result.exit_code, result.output)
        self.store.record_run(name, tool.name, command, result.exit_code, summary)
        self.store.save_flags(name, tool.name, command)
        self._last_output = result.output
        self._log(summary)
        self.refresh_detail()

    def _log(self, line: str) -> None:
        self._log_lines.append(line)
        self.query_one("#log", Static).update("\n".join(self._log_lines[-6:]))

    @work
    async def action_run_pipeline(self) -> None:
        name = self._current_target()
        if not name:
            self.notify("Add and select a target first.", severity="warning")
            return
        names = ", ".join(p.name for p in self.pipelines)
        choice = await self.push_screen_wait(PromptModal(
            "Run pipeline", initial=self.pipelines[0].name if self.pipelines else "",
            confirm_label="Run", note=f"available: {names}"))
        if not choice:
            return
        pipe = next((p for p in self.pipelines if p.name == choice.strip()), None)
        if not pipe:
            self.notify(f"No pipeline named {choice!r}.", severity="warning")
            return
        tvals = target_values(name)
        proxy = (self.store.get_target(name) or {}).get("proxy") or None
        by_name = {t.name: t for t in self.catalog}
        self._log(f"▶ pipeline {pipe.name} ({len(pipe.steps)} steps)")
        for step in pipe.steps:
            tool = by_name.get(step)
            if tool is None:
                self._log(f"{step} · skipped · not in catalog")
                continue
            command, reason = build_command(tool, tvals, lambda n: self.store.get_flags(name, n))
            if command is None:
                self._log(f"{step} · skipped · {reason}")
                continue
            self.notify(f"{pipe.name}: running {step}…")
            result = await asyncio.to_thread(run_tool, command, proxy)
            summary = summarize(step, result.exit_code, result.output)
            self.store.record_run(name, step, command, result.exit_code, summary)
            self.store.save_flags(name, step, command)
            self._last_output = result.output
            self._log(summary)
            if pipe.stop_on_error and result.exit_code != 0:
                self._log(f"■ stopped on error at {step}")
                break
        self._log(f"✓ pipeline {pipe.name} done")
        self.refresh_detail()

    @work
    async def action_haruspex_hint(self) -> None:
        if not self._suggestions:
            self.notify("No suggestions to rank.")
            return
        name = self._current_target() or ""
        target = self.store.get_target(name) or {}
        options = [s.tool for s in self._suggestions if s.tool]
        if not options:
            self.notify("Top action is manual — nothing to rank.")
            return
        ranked = await asyncio.to_thread(
            haruspex.rank_candidates,
            "Which tool should the operator run next on this target?",
            options, name, ",".join(target.get("tech") or []))
        if not ranked:
            self.notify("Haruspex: no call (abstained or offline).")
            return
        order = {tool: i for i, tool in enumerate(ranked)}
        self._suggestions = sorted(
            self._suggestions,
            key=lambda s: order.get(s.tool, len(order)) if s.tool else len(order) + 1)
        self.query_one("#nextaction", Static).update(
            self._format_suggestions(self.store.findings_for_target(name)) + "\n[dim](ordered by Haruspex)[/dim]")
        self.notify("Haruspex re-ranked the next actions.")

    def action_full_output(self) -> None:
        if self._last_output:
            self.query_one("#log", Static).update(self._last_output[-4000:])
        else:
            self.notify("No tool output yet.")


def build_app() -> OptioApp:
    return OptioApp()
