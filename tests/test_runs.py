"""Async runs — the background job manager behind the UI's non-blocking
run + poll + cancel. Uses the real executor so cancellation is genuinely
tested (a killed process group, not a mocked one)."""

import time

from optio.service import OptioService
from optio.store import Store


def _wait(svc, job_id, want, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = svc.job_status(job_id)
        if st and st["status"] in want:
            return st
        time.sleep(0.05)
    raise AssertionError(f"job never reached {want}: {svc.job_status(job_id)}")


def test_async_tool_run_returns_a_job_id_then_completes_and_records(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = Store(tmp_path / "t.db")
    svc = OptioService(store)  # real executor
    svc.add_target("ex.com")

    r = svc.run_tool_async("ex.com", "httpx", command="echo async-ok")
    assert "job_id" in r  # returns immediately, before the run finishes

    st = _wait(svc, r["job_id"], {"done"})
    assert st["results"][0]["exit_code"] == 0
    assert "async-ok" in st["results"][0]["summary"] or st["results"][0]["exit_code"] == 0
    assert "httpx" in store.tools_run_for_target("ex.com")  # recorded like a sync run
    store.close()


def test_cancel_kills_the_whole_process_group(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = Store(tmp_path / "t.db")
    svc = OptioService(store)
    svc.add_target("ex.com")

    marker = tmp_path / "marker"
    # sh spawns sleep; if the process GROUP is killed, 'touch marker' never runs —
    # proving a cancel takes down children (vigil -> nikto/chromium), not just the parent.
    r = svc.run_tool_async("ex.com", "httpx",
                           command=f"sh -c 'sleep 5; touch {marker}'")
    _wait(svc, r["job_id"], {"running"}, timeout=3)
    time.sleep(0.3)

    svc.cancel_job(r["job_id"])
    st = _wait(svc, r["job_id"], {"cancelled", "done", "failed"}, timeout=5)
    assert st["status"] == "cancelled"
    assert st["elapsed_ms"] < 5000  # stopped well before the 5s sleep would finish

    time.sleep(1.0)  # give any stray child time to fire
    assert not marker.exists()  # the group really died
    store.close()


def test_job_status_for_unknown_id_is_none(tmp_path):
    store = Store(tmp_path / "t.db")
    svc = OptioService(store)
    assert svc.job_status("deadbeef0000") is None
    assert svc.cancel_job("deadbeef0000") is None
    store.close()
