"""Optional Haruspex ranking hint.

Haruspex is a small, local, calibrated decision layer that scores a bounded set
of options and ABSTAINS when unsure. Optio uses it the same way Praetor does: a
local HTTP ``POST /v1/evaluate``, keyless, auto-detected on port 3000. It is a
hint, never a decider — the operator still picks.

Fail-open by construction: if Haruspex is not running, slow, or returns anything
unexpected, every call returns None (no hint) and never raises. Stdlib only.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:3000"


def default_url() -> str:
    # Optio-native var first (a user who never touches Praetor configures this),
    # then the generic var, then a Praetor var last for a shared single-host box.
    return (os.environ.get("OPTIO_HARUSPEX_URL")
            or os.environ.get("HARUSPEX_URL")
            or os.environ.get("PRAETOR_DECISION_BASE_URL")
            or DEFAULT_URL)


def evaluate(question: str, candidates: dict[str, str], target: str = "",
             domain: str = "", url: str | None = None, timeout: float = 1.5) -> dict | None:
    """Ask Haruspex to judge a bounded option set. None on any failure (fail-open)."""
    base = (url or default_url()).rstrip("/")
    payload = {"question": question, "candidates": candidates, "target": target}
    if domain:
        payload["domain"] = domain
    try:
        req = urllib.request.Request(
            base + "/v1/evaluate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def rank_candidates(question: str, options: list[str], target: str = "",
                    domain: str = "", url: str | None = None,
                    timeout: float = 1.5) -> list[str] | None:
    """Order ``options`` by Haruspex's confidence. None when it abstains or is down.

    Returns the options sorted best-first using the verdict's probability
    distribution, or None if Haruspex is unreachable or gives no usable answer.
    """
    if not options:
        return None
    result = evaluate(question, {o: o for o in options}, target, domain, url, timeout)
    if not isinstance(result, dict):
        return None
    # Accept the common shapes: a {option: probability} map, or a list of
    # {label/option, probability} entries. Anything else -> no hint.
    probs = result.get("probabilities") or result.get("distribution") or result.get("scores")
    pairs: list[tuple[str, float]] = []
    if isinstance(probs, dict):
        pairs = [(k, float(v)) for k, v in probs.items() if k in options]
    elif isinstance(probs, list):
        for item in probs:
            if isinstance(item, dict):
                label = item.get("label") or item.get("option") or item.get("candidate")
                p = item.get("probability", item.get("score"))
                if label in options and p is not None:
                    pairs.append((label, float(p)))
    if not pairs:
        return None
    pairs.sort(key=lambda kv: kv[1], reverse=True)
    ranked = [k for k, _ in pairs]
    # keep any options Haruspex did not rank, in their original order
    ranked += [o for o in options if o not in ranked]
    return ranked
