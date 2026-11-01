"""Run a tool as a subprocess and capture its output.

Optio owns execution, so it never injects keystrokes into another shell (the
fragile part of arsenal). It splits the rendered command safely — no
``shell=True`` — and optionally routes the child's HTTP traffic through a proxy
the operator configured (e.g. Burp). A missing binary is reported, not raised:
the TUI shows it as a failed run, never a crash.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    output: str


def run(command: str, proxy: str | None = None, timeout: int | None = None,
        cwd: str | None = None) -> RunResult:
    argv = shlex.split(command)
    if not argv:
        return RunResult(exit_code=1, output="empty command")

    env = dict(os.environ)
    if proxy:
        env["HTTP_PROXY"] = env["http_proxy"] = proxy
        env["HTTPS_PROXY"] = env["https_proxy"] = proxy

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env, cwd=cwd,
            timeout=timeout,
        )
    except FileNotFoundError:
        return RunResult(exit_code=127, output=f"binary not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        return RunResult(exit_code=124, output=f"timed out after {timeout}s")

    output = (proc.stdout or "") + (proc.stderr or "")
    return RunResult(exit_code=proc.returncode, output=output)
