"""The next-action advisor.

A deterministic priority ladder over the target's state — no model, no autopilot.
It returns ranked suggestions; the operator decides. The order mirrors a sound
engagement:

0. Verify a suspected lead before scanning more — a lead beats a new scan.
1. Prove impact / chain a confirmed finding.
2. Walk the flow phases in order (recon -> surface -> scan -> probe); suggest the
   first phase that still has an un-run tool. In the probe phase, order the tools
   by the tech stack's class priorities.
3. Fully covered with nothing found -> change approach (manual authz / logic /
   chaining), not another scan.
4. Fully covered with findings -> review and report.

An optional Haruspex hook can re-rank the candidates; it is not required and the
ladder stands on its own.
"""

from __future__ import annotations

from dataclasses import dataclass

from optio.catalog import Tool
from optio.flow import PHASE_ORDER
from optio.knowledge import CLASS_TO_TOOL, classes_for_tech

_OPEN_STATUSES = {"suspected", "unconfirmed", "", None}


@dataclass(frozen=True)
class Suggestion:
    action: str
    reason: str
    priority: int
    tool: str | None = None
    command: str | None = None
    phase: str | None = None


def _render(tool: Tool, target_values: dict[str, str] | None) -> str | None:
    if not target_values or tool.missing_placeholders(target_values):
        return None
    return tool.render(target_values)


def _class_priority(tech: list[str]) -> dict[str, int]:
    return {cls: i for i, cls in enumerate(classes_for_tech(tech))}


def suggest(
    catalog: list[Tool],
    tech: list[str],
    tools_run: set[str],
    findings: list[dict],
    target_values: dict[str, str] | None = None,
    max_suggestions: int = 6,
) -> list[Suggestion]:
    out: list[Suggestion] = []
    class_rank = _class_priority(tech)

    # 0 — verify suspected leads first.
    for f in findings:
        if (f.get("status") or "") in _OPEN_STATUSES:
            cls = (f.get("vuln_class") or "unknown").lower()
            endpoint = f.get("endpoint") or "?"
            tool = CLASS_TO_TOOL.get(cls)
            cmd = None
            if tool:
                t = next((x for x in catalog if x.name == tool), None)
                if t:
                    cmd = _render(t, target_values)
            out.append(Suggestion(
                action=f"Verify the {cls} lead on {endpoint}",
                reason="A suspected lead is worth more than a new scan. Confirm it before moving on.",
                priority=0, tool=tool, command=cmd, phase="verify"))

    # 1 — prove impact of confirmed findings.
    for f in findings:
        if (f.get("status") or "") == "confirmed":
            cls = (f.get("vuln_class") or "unknown").lower()
            endpoint = f.get("endpoint") or "?"
            out.append(Suggestion(
                action=f"Prove impact of the confirmed {cls} on {endpoint}",
                reason="What can an attacker GAIN? Escalate or chain it before you report.",
                priority=1, tool=None, command=None, phase="report"))

    # 2 — walk the flow phases; fill the first one with an un-run tool.
    phase_done: dict[str, bool] = {}
    for phase in PHASE_ORDER:
        phase_tools = [t for t in catalog if t.phase == phase]
        if not phase_tools:
            continue
        unrun = [t for t in phase_tools if t.name not in tools_run]
        phase_done[phase] = not unrun
        if unrun:
            # In the probe phase, order by the tech stack's class priorities.
            if phase == "probe":
                def key(t: Tool) -> int:
                    ranks = [class_rank.get(c, 99) for c in t.classes] or [99]
                    return min(ranks)
                unrun = sorted(unrun, key=key)
            base = 2 + PHASE_ORDER.index(phase)
            for i, t in enumerate(unrun):
                out.append(Suggestion(
                    action=f"Run {t.name} ({phase})",
                    reason=t.description or f"{phase} step.",
                    priority=base + i, tool=t.name,
                    command=_render(t, target_values), phase=phase))
            break  # only the earliest open phase

    # 3 / 4 — fully covered.
    catalog_tools = {t.name for t in catalog}
    if catalog_tools and catalog_tools <= tools_run and not any(s.phase not in (None, "verify", "report") for s in out):
        if not findings:
            out.append(Suggestion(
                action="Change approach — no leads yet",
                reason="Full tool coverage with nothing found. Test authorization (IDOR/BOLA) "
                       "across roles, business logic, and chain any low-value observations.",
                priority=10, tool=None, command=None, phase=None))
        elif not any(s.priority <= 1 for s in out):
            out.append(Suggestion(
                action="Review findings and report",
                reason="Tools are covered and findings exist. Review impact, chain where possible, write them up.",
                priority=11, tool=None, command=None, phase="report"))

    out.sort(key=lambda s: s.priority)
    return out[:max_suggestions]
