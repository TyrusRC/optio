"""The command-palette matcher.

The operator types a word; this ranks every catalog tool and pipeline against
it so they never have to remember which of ~70 tools does the thing they want.
Pure logic — ``OptioCommands`` (the Textual provider, in app.py) is thin glue
that turns a ``Command`` into a launch.

Ranking, best first:
    0  name starts with the query
    1  query appears elsewhere in the name
    2  query appears in the description
Tools rank ahead of pipelines at the same tier. An empty query lists all.
"""

from __future__ import annotations

from dataclasses import dataclass

from optio.catalog import Tool
from optio.flow import phase_rank
from optio.pipeline import Pipeline


@dataclass(frozen=True)
class Command:
    title: str   # human line shown in the palette
    kind: str    # "tool" | "pipeline"
    name: str    # catalog/pipeline name to launch


def _rank(name: str, description: str, q: str) -> int | None:
    name, description = name.lower(), description.lower()
    if not q:
        return 0
    if name.startswith(q):
        return 0
    if q in name:
        return 1
    if q in description:
        return 2
    return None


def match_commands(catalog: list[Tool], pipelines: list[Pipeline], query: str) -> list[Command]:
    q = query.strip().lower()
    scored: list[tuple[int, int, int, Command]] = []

    for t in catalog:
        r = _rank(t.name, t.description, q)
        if r is not None:
            title = f"run {t.name} — {t.description}" if t.description else f"run {t.name}"
            scored.append((r, 0, phase_rank(t.phase), Command(title, "tool", t.name)))

    for p in pipelines:
        r = _rank(p.name, p.description, q)
        if r is not None:
            title = f"pipeline {p.name} — {p.description}" if p.description else f"pipeline {p.name}"
            scored.append((r, 1, 0, Command(title, "pipeline", p.name)))

    scored.sort(key=lambda s: (s[0], s[1], s[2], s[3].name))
    return [c for *_, c in scored]
