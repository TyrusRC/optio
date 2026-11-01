"""Render findings into a report a reader acts on.

A tracked finding is internal bookkeeping; a report is the deliverable. This
projects findings to markdown the way a pentest report reads: an executive
summary that frames risk (a severity breakdown, never an activity count) then
per-finding detail with an evidence snapshot. A field that was never captured
prints ``*NOT SUPPLIED*`` so the gap shows instead of being filled from memory.

Pure function — no store, no I/O. Pass ``request_lookup`` to resolve a finding's
``evidence_request_id`` into a captured request/response snapshot.
"""

from __future__ import annotations

from collections.abc import Callable

_SEV_ORDER = ["critical", "high", "medium", "low"]
_NOT_SUPPLIED = "*NOT SUPPLIED*"

RequestLookup = Callable[[int], dict | None]


def render_markdown(target: str, findings: list[dict], *, audience: str = "client",
                    request_lookup: RequestLookup | None = None) -> str:
    """Markdown report for ``target``. ``audience='client'`` renders only
    confirmed findings; ``'internal'`` renders every finding passed."""
    shown = findings if audience == "internal" else [
        f for f in findings if (f.get("status") or "") == "confirmed"]

    out: list[str] = [f"# Security Assessment — {target}", ""]
    out += _executive_summary(shown)
    if not shown:
        out += ["", "No confirmed findings to report."]
        return "\n".join(out)

    out += ["", "## Findings", ""]
    for i, f in enumerate(shown, 1):
        out += _finding_section(i, f, request_lookup)
    return "\n".join(out)


def _executive_summary(shown: list[dict]) -> list[str]:
    out = ["## Executive Summary", ""]
    if not shown:
        out.append("No confirmed findings were identified in the assessed scope.")
        return out
    counts = {sev: 0 for sev in _SEV_ORDER}
    for f in shown:
        counts[(f.get("severity") or "low").lower()] = counts.get((f.get("severity") or "low").lower(), 0) + 1
    breakdown = ", ".join(f"{counts[s]} {s.upper()}" for s in _SEV_ORDER if counts.get(s))
    out.append(f"The assessment identified the following confirmed issues: {breakdown}.")
    top = [f for f in shown if (f.get("severity") or "").lower() in ("critical", "high")]
    if top:
        out.append("")
        out.append("The highest-risk issues require attention first:")
        for f in top:
            out.append(f"- **{f.get('title', '?')}** ({(f.get('severity') or '').upper()}) — "
                       f"{f.get('impact') or 'impact not stated'}")
    return out


def _finding_section(i: int, f: dict, lookup: RequestLookup | None) -> list[str]:
    sev = (f.get("severity") or "low").upper()
    out = [f"### {i}. {f.get('title', '?')}", "",
           f"- **Severity:** {sev}",
           f"- **CVSS:** {f.get('cvss') or _NOT_SUPPLIED}",
           f"- **CWE:** {f.get('cwe') or _NOT_SUPPLIED}",
           f"- **Affected:** {f.get('endpoint') or _NOT_SUPPLIED}", ""]
    out += ["**Impact**", "", f.get("impact") or _NOT_SUPPLIED, ""]
    out += ["**Reproduction**", "", f.get("reproduction") or _NOT_SUPPLIED, ""]
    out += ["**Evidence**", ""]
    out += _evidence_block(f, lookup)
    out += ["", "**Remediation**", "", f.get("remediation") or _NOT_SUPPLIED, ""]
    return out


def _evidence_block(f: dict, lookup: RequestLookup | None) -> list[str]:
    rid = f.get("evidence_request_id")
    snap = lookup(rid) if (rid and lookup) else None
    if not snap:
        return [_NOT_SUPPLIED]
    body = (snap.get("resp_body") or "")[:500]
    return ["```",
            f"{snap.get('method', '?')} {snap.get('url', '?')}",
            f"-> {snap.get('status', '?')} ({snap.get('elapsed_ms', 0)} ms)",
            "",
            body,
            "```"]
