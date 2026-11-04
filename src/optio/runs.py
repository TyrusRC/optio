"""Background job manager for long-running tool and pipeline runs.

A scan (vigil chaining nikto + a headless browser) can take tens of minutes.
Running it inside the HTTP request would pin a worker thread and leave the UI
with nothing but a spinner and no way to stop it. Instead the service submits
the work here: ``submit`` returns immediately with a job id, the UI polls
``get`` for status + elapsed time, and ``cancel`` kills the running subprocess
(and its process group, via the executor) on demand.

In-memory and single-process — fine for a loopback cockpit. The registry is
pruned to the most recent jobs so it can't grow without bound.
NOTE: jobs don't survive a server restart; that's acceptable for a local tool.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from subprocess import Popen

from optio.executor import kill_process_group

_MAX_JOBS = 200  # keep the most recent; drop older finished jobs beyond this


class Job:
    def __init__(self, kind: str, label: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind            # 'tool' | 'pipeline'
        self.label = label
        self.status = "running"     # running | done | failed | cancelled
        self.started_at = time.time()
        self.ended_at: float | None = None
        self.results: list[dict] = []
        self.error: str | None = None
        self._proc: Popen | None = None
        self._cancelled = threading.Event()
        self._lock = threading.Lock()

    # ── worker-side hooks ────────────────────────────────────────────────
    def set_proc(self, proc: Popen) -> None:
        """The executor calls this when a subprocess starts. If a cancel already
        arrived, kill it at once — closing the race between submit and spawn."""
        with self._lock:
            self._proc = proc
            if self._cancelled.is_set():
                kill_process_group(proc)

    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    # ── reader-side ──────────────────────────────────────────────────────
    def snapshot(self) -> dict:
        end = self.ended_at if self.ended_at is not None else time.time()
        return {
            "id": self.id, "kind": self.kind, "label": self.label,
            "status": self.status,
            "elapsed_ms": int((end - self.started_at) * 1000),
            "results": self.results, "error": self.error,
        }

    def _request_cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            if self._proc is not None:
                kill_process_group(self._proc)


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, label: str, fn: Callable[[Job], None]) -> Job:
        """Run ``fn(job)`` in a daemon thread. ``fn`` does the work and appends
        to ``job.results``; it should run subprocesses with ``on_start=job.set_proc``
        and check ``job.cancelled()`` between steps so a cancel takes effect."""
        job = Job(kind, label)
        with self._lock:
            self._jobs[job.id] = job
            self._prune()

        def _worker() -> None:
            try:
                fn(job)
                if job.status == "running":
                    job.status = "cancelled" if job.cancelled() else "done"
            except Exception as e:  # a worker crash becomes a failed job, never a dead thread
                job.status = "failed"
                job.error = str(e)
            finally:
                job.ended_at = time.time()

        threading.Thread(target=_worker, daemon=True).start()
        return job

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
        return job.snapshot() if job else None

    def cancel(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return None
        job._request_cancel()
        return job.snapshot()

    def _prune(self) -> None:
        """Caller holds the lock. Drop the oldest finished jobs past the cap."""
        if len(self._jobs) <= _MAX_JOBS:
            return
        finished = sorted(
            (j for j in self._jobs.values() if j.ended_at is not None),
            key=lambda j: j.ended_at or 0,
        )
        for j in finished[: len(self._jobs) - _MAX_JOBS]:
            self._jobs.pop(j.id, None)
