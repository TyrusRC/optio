"""Pipelines — run a named chain of catalog tools in order.

A pipeline reduces the manual pick-confirm-run loop: the operator triggers one
chain and Optio walks its steps, building each command (from flag memory or the
tool template), running it, summarizing, and recording the run. A step whose
command still has an unfilled placeholder is skipped rather than run broken. With
``stop_on_error`` the chain halts on the first non-zero exit.

The runner and recorder are injected, so the chain logic is testable without a
live subprocess or a database.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from optio.catalog import Tool
from optio.executor import RunResult
from optio.summarize import summarize


@dataclass(frozen=True)
class Pipeline:
    name: str
    description: str
    steps: list[str]
    stop_on_error: bool = False


@dataclass(frozen=True)
class StepResult:
    tool: str
    command: str
    exit_code: int | None
    summary: str
    skipped: bool = False
    reason: str = ""


def _pipes_from_doc(doc: dict) -> list[Pipeline]:
    out: list[Pipeline] = []
    for raw in (doc or {}).get("pipelines", []):
        out.append(Pipeline(
            name=raw["name"],
            description=raw.get("description", ""),
            steps=list(raw.get("steps", [])),
            stop_on_error=bool(raw.get("stop_on_error", False)),
        ))
    return out


def load_default_pipelines() -> list[Pipeline]:
    text = resources.files("optio.data").joinpath("pipelines.yaml").read_text(encoding="utf-8")
    return _pipes_from_doc(yaml.safe_load(text))


def load_pipelines(paths: list[Path]) -> list[Pipeline]:
    by_name: dict[str, Pipeline] = {}
    for path in paths:
        if not path.exists():
            continue
        for p in _pipes_from_doc(yaml.safe_load(path.read_text(encoding="utf-8"))):
            by_name[p.name] = p
    return list(by_name.values())


def build_command(tool: Tool, target_values: dict[str, str],
                   flag_lookup: Callable[[str], str | None]) -> tuple[str | None, str]:
    """Return (command, reason). command is None when a required value is missing."""
    remembered = flag_lookup(tool.name)
    if remembered:
        return remembered, ""
    missing = tool.missing_placeholders(target_values)
    if missing:
        return None, f"needs input: {', '.join(missing)}"
    return tool.render(target_values), ""


def run_pipeline(
    pipeline: Pipeline,
    tools_by_name: dict[str, Tool],
    target_values: dict[str, str],
    flag_lookup: Callable[[str], str | None],
    runner: Callable[[str], RunResult],
    recorder: Callable[[str, str, int | None, str], None] | None = None,
    summarizer: Callable[[str, int, str], str] = summarize,
    cancelled: Callable[[], bool] = lambda: False,
) -> list[StepResult]:
    results: list[StepResult] = []
    for name in pipeline.steps:
        if cancelled():  # a cancel between steps stops the chain cleanly
            break
        tool = tools_by_name.get(name)
        if tool is None:
            results.append(StepResult(name, "", None, f"{name}: unknown tool",
                                      skipped=True, reason="not in catalog"))
            continue
        command, reason = build_command(tool, target_values, flag_lookup)
        if command is None:
            results.append(StepResult(name, "", None, f"{name} · skipped · {reason}",
                                      skipped=True, reason=reason))
            continue
        result = runner(command)
        summary = summarizer(name, result.exit_code, result.output)
        if recorder:
            recorder(name, command, result.exit_code, summary)
        results.append(StepResult(name, command, result.exit_code, summary))
        if pipeline.stop_on_error and result.exit_code != 0:
            break
    return results
