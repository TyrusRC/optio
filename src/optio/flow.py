"""The engagement flow — the ordered phases a target moves through.

Each catalog tool declares which phase it belongs to. The advisor walks the
phases in this order and suggests the first phase that still has an un-run,
applicable tool. The operator always decides; this is the rail, not autopilot.
"""

from __future__ import annotations

# Ordered. The advisor fills earlier phases before later ones.
PHASE_ORDER: list[str] = ["recon", "surface", "scan", "probe", "verify", "report"]

PHASE_DESCRIPTION: dict[str, str] = {
    "recon": "Map the attack surface — hosts, live services, tech stack.",
    "surface": "Enumerate endpoints, parameters, and content.",
    "scan": "Run broad vulnerability scanners for leads.",
    "probe": "Test high-value classes against the parameters found.",
    "verify": "Reproduce and prove the impact of each lead.",
    "report": "Review findings, chain for impact, write them up.",
}


def phase_rank(phase: str) -> int:
    """Index of a phase in the flow; unknown phases sort last."""
    try:
        return PHASE_ORDER.index(phase)
    except ValueError:
        return len(PHASE_ORDER)
