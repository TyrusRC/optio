"""The subprocess executor and the generic output summarizer."""

import sys

from optio.executor import run
from optio.summarize import summarize


def test_run_captures_output_and_exit_code():
    r = run("echo hello-optio")
    assert r.exit_code == 0
    assert "hello-optio" in r.output


def test_run_reports_nonzero_exit():
    r = run(f"{sys.executable} -c \"import sys; sys.exit(3)\"")
    assert r.exit_code == 3


def test_run_injects_proxy_env():
    cmd = f"{sys.executable} -c \"import os; print(os.environ.get('HTTP_PROXY',''))\""
    r = run(cmd, proxy="http://127.0.0.1:8080")
    assert "http://127.0.0.1:8080" in r.output


def test_run_missing_binary_is_reported_not_raised():
    r = run("definitely-not-a-real-binary-xyz foo")
    assert r.exit_code != 0
    assert r.output  # a message, not a crash


def test_summary_names_exit_and_line_count():
    s = summarize("nuclei", exit_code=0, output="a\nb\nc")
    assert "nuclei" in s
    assert "3" in s  # 3 lines


def test_summary_handles_empty_output():
    s = summarize("ffuf", exit_code=0, output="")
    assert "ffuf" in s
