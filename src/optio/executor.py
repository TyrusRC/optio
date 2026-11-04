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
import signal
import subprocess
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    output: str


def kill_process_group(proc: subprocess.Popen) -> None:
    """SIGTERM the child's whole process group, so a long scanner that spawns
    helpers (vigil -> nikto, chromium) dies with it instead of orphaning them.
    Falls back to terminating just the child where process groups aren't available."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        try:
            proc.terminate()
        except OSError:
            pass


def run(command: str, proxy: str | None = None, timeout: int | None = None,
        cwd: str | None = None,
        on_start: Callable[[subprocess.Popen], None] | None = None) -> RunResult:
    """Run ``command`` as a subprocess and capture its combined output.

    ``on_start`` is called with the live ``Popen`` right after spawn so a caller
    (the async job manager) can register it for cancellation. The child runs in
    its own process group so a cancel/timeout can take down the whole tree."""
    argv = shlex.split(command)
    if not argv:
        return RunResult(exit_code=1, output="empty command")

    env = dict(os.environ)
    if proxy:
        env["HTTP_PROXY"] = env["http_proxy"] = proxy
        env["HTTPS_PROXY"] = env["https_proxy"] = proxy

    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env, cwd=cwd, start_new_session=True,
        )
    except FileNotFoundError:
        return RunResult(exit_code=127, output=f"binary not found: {argv[0]}")

    if on_start is not None:
        on_start(proc)

    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_process_group(proc)
        proc.communicate()
        return RunResult(exit_code=124, output=f"timed out after {timeout}s")

    return RunResult(exit_code=proc.returncode, output=(out or "") + (err or ""))
