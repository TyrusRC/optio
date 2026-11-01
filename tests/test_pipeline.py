"""Pipelines — run a named chain of tools in order, recording each run.

Reduces the manual pick-confirm-run loop: trigger one pipeline, it walks the
steps. A step whose command still has an unfilled placeholder (e.g. {wordlist})
is skipped, not run with a broken command. stop_on_error halts the chain.
"""

from optio.catalog import load_default_catalog
from optio.executor import RunResult
from optio.pipeline import Pipeline, load_default_pipelines, run_pipeline

CAT = {t.name: t for t in load_default_catalog()}
TVALS = {"domain": "ex.com", "url": "https://ex.com", "host": "ex.com"}


def _fake_runner(calls):
    def runner(command):
        calls.append(command)
        return RunResult(exit_code=0, output=f"ran: {command}")
    return runner


def test_default_pipelines_loaded():
    pipes = load_default_pipelines()
    names = {p.name for p in pipes}
    assert "recon-sweep" in names
    assert all(isinstance(p, Pipeline) for p in pipes)


def test_run_pipeline_runs_steps_in_order():
    calls = []
    pipe = Pipeline(name="t", description="", steps=["subfinder", "httpx"])
    results = run_pipeline(pipe, CAT, TVALS, flag_lookup=lambda n: None,
                           runner=_fake_runner(calls))
    assert [r.tool for r in results] == ["subfinder", "httpx"]
    assert calls[0].startswith("subfinder -d ex.com")
    assert calls[1].startswith("httpx -u https://ex.com")
    assert all(r.exit_code == 0 and not r.skipped for r in results)


def test_step_needing_input_is_skipped_not_run():
    calls = []
    # ffuf needs {wordlist}, which TVALS does not provide, and no flag memory
    pipe = Pipeline(name="t", description="", steps=["ffuf", "httpx"])
    results = run_pipeline(pipe, CAT, TVALS, flag_lookup=lambda n: None,
                           runner=_fake_runner(calls))
    assert results[0].tool == "ffuf" and results[0].skipped
    assert "wordlist" in results[0].reason
    assert len(calls) == 1 and calls[0].startswith("httpx")  # only httpx ran


def test_flag_memory_supplies_the_command():
    calls = []
    pipe = Pipeline(name="t", description="", steps=["ffuf"])
    results = run_pipeline(pipe, CAT, TVALS,
                           flag_lookup=lambda n: "ffuf -u https://ex.com/FUZZ -w /tmp/w.txt",
                           runner=_fake_runner(calls))
    assert not results[0].skipped
    assert calls == ["ffuf -u https://ex.com/FUZZ -w /tmp/w.txt"]


def test_stop_on_error_halts_the_chain():
    def failing_runner(command):
        return RunResult(exit_code=1 if "subfinder" in command else 0, output="x")
    pipe = Pipeline(name="t", description="", steps=["subfinder", "httpx"], stop_on_error=True)
    results = run_pipeline(pipe, CAT, TVALS, flag_lookup=lambda n: None, runner=failing_runner)
    assert len(results) == 1 and results[0].exit_code == 1


def test_recorder_called_per_run():
    recorded = []
    pipe = Pipeline(name="t", description="", steps=["subfinder"])
    run_pipeline(pipe, CAT, TVALS, flag_lookup=lambda n: None,
                 runner=_fake_runner([]),
                 recorder=lambda tool, cmd, code, summary: recorded.append((tool, code)))
    assert recorded == [("subfinder", 0)]
