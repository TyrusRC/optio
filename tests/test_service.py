"""The OptioService facade — the programmatic API automation uses (no TUI)."""

import pytest

from optio.executor import RunResult
from optio.service import OptioService
from optio.store import Store


def _fake_runner(calls):
    def runner(command, proxy=None):
        calls.append((command, proxy))
        return RunResult(exit_code=0, output=f"ran: {command}")
    return runner


@pytest.fixture
def svc(tmp_path):
    store = Store(tmp_path / "t.db")
    s = OptioService(store, runner=_fake_runner([]))
    yield s
    store.close()


def test_add_and_list_targets(svc):
    svc.add_target("ex.com", tech=["php"])
    assert [t["name"] for t in svc.list_targets()] == ["ex.com"]
    assert svc.get_target("ex.com")["tech"] == ["php"]


def test_catalog_and_pipelines_exposed(svc):
    assert any(t["name"] == "nuclei" for t in svc.catalog_list())
    assert any(p["name"] == "recon-sweep" for p in svc.pipeline_list())


def test_next_actions_for_fresh_target(svc):
    svc.add_target("ex.com", tech=["php"])
    actions = svc.next_actions("ex.com")
    assert actions and actions[0]["phase"] == "recon"
    assert "tool" in actions[0]


def test_run_tool_records_and_returns(tmp_path):
    calls = []
    store = Store(tmp_path / "t.db")
    svc = OptioService(store, runner=_fake_runner(calls))
    svc.add_target("ex.com")
    res = svc.run_tool("ex.com", "subfinder")
    assert res["exit_code"] == 0
    assert res["command"].startswith("subfinder -d ex.com")
    assert "subfinder" in svc.coverage("ex.com")["ran"]
    assert calls[0][0].startswith("subfinder -d ex.com")
    store.close()


def test_run_tool_missing_input_is_error_not_crash(tmp_path):
    store = Store(tmp_path / "t.db")
    svc = OptioService(store, runner=_fake_runner([]))
    svc.add_target("ex.com")
    res = svc.run_tool("ex.com", "ffuf")  # needs {wordlist}
    assert res.get("error")
    assert "wordlist" in res["error"]
    store.close()


def test_run_tool_explicit_command_is_used(tmp_path):
    calls = []
    store = Store(tmp_path / "t.db")
    svc = OptioService(store, runner=_fake_runner(calls))
    svc.add_target("ex.com")
    svc.run_tool("ex.com", "ffuf", command="ffuf -u https://ex.com/FUZZ -w /tmp/w")
    assert calls[0][0] == "ffuf -u https://ex.com/FUZZ -w /tmp/w"


def test_run_pipeline(tmp_path):
    calls = []
    store = Store(tmp_path / "t.db")
    svc = OptioService(store, runner=_fake_runner(calls))
    svc.add_target("ex.com")
    steps = svc.run_pipeline("ex.com", "recon-sweep")
    tools_ran = [s["tool"] for s in steps if not s.get("skipped")]
    assert "subfinder" in tools_ran and "httpx" in tools_ran


def test_findings_roundtrip(svc):
    svc.add_target("ex.com")
    svc.add_finding("ex.com", title="SQLi", vuln_class="sqli", endpoint="/x", severity="high")
    f = svc.findings("ex.com")
    assert len(f) == 1 and f[0]["vuln_class"] == "sqli"
