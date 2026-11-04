"""Turn a tool's raw output into a short line for the activity log.

The noise rule: the board shows the signal, never the firehose. The generic
summarizer gives the status, the output size, and the last meaningful line.
Tool-specific summarizers can be added later, keyed by tool name.
"""

from __future__ import annotations

import re

# Many CLI tools colour their output; the codes are noise in a one-line summary
# (and show as garbage in the web status bar). Strip them at the source.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def summarize(tool: str, exit_code: int, output: str) -> str:
    clean = _ANSI.sub("", output or "")
    lines = [ln for ln in clean.splitlines() if ln.strip()]
    status = "ok" if exit_code == 0 else f"exit {exit_code}"
    if not lines:
        return f"{tool} · {status} · no output"
    tail = lines[-1].strip()
    if len(tail) > 80:
        tail = tail[:77] + "..."
    return f"{tool} · {status} · {len(lines)} lines · {tail}"
