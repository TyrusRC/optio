"""Smart auto-run — run the sensible early flow unattended to save time.

It walks recon -> surface -> scan in value order, running each tool whose
command can be filled from the target, and stops before the probe phase (probing
is targeted and heavier — the operator decides those). Tools needing an unfilled
placeholder (e.g. a wordlist) are skipped, not retried forever.
"""

from optio.catalog import Tool
from optio.service import OptioService
from optio.store import Store

CATALOG = [
    Tool(name="subfinder", binary="subfinder", lane="recon", phase="recon",
         template="subfinder -d {domain}", scope="web"),
    Tool(name="katana", binary="katana", lane="recon", phase="surface",
         template="katana -u {url}", scope="web"),
    Tool(name="ffuf", binary="ffuf", lane="web-scan", phase="surface",
         template="ffuf -u {url}/FUZZ -w {wordlist}", scope="web"),  # needs a wordlist
    Tool(name="nuclei", binary="nuclei", lane="web-scan", phase="scan",
         template="nuclei -u {url}", scope="web"),
    Tool(name="sqlmap", binary="sqlmap", lane="web-scan", phase="probe",
         classes=["sqli"], template="sqlmap -u {url}", scope="web"),
]


def _svc(tmp_path):
    ran = []
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com", tech=["php"])

    def runner(command, proxy=None, cwd=None):
        from optio.executor import RunResult
        ran.append(command)
        return RunResult(exit_code=0, output="ok")

    svc = OptioService(s, catalog=CATALOG, pipelines=[], runner=runner,
                       ranker=lambda o, t, k: None)
    return svc, s, ran


def test_auto_run_walks_recon_surface_scan_and_stops_before_probe(tmp_path):
    svc, store, ran = _svc(tmp_path)
    out = svc.auto_run("ex.com")
    tools_ran = [s["tool"] for s in out["steps"] if "command" in s]
    assert tools_ran == ["subfinder", "katana", "nuclei"]   # value order, no probe
    assert "sqlmap" not in [s["tool"] for s in out["steps"]]  # probe excluded
    assert any("sqlmap" in c for c in ran) is False
    store.close()


def test_auto_run_skips_unfillable_tool_without_looping(tmp_path):
    svc, store, ran = _svc(tmp_path)
    out = svc.auto_run("ex.com")
    ffuf = next(s for s in out["steps"] if s["tool"] == "ffuf")
    assert "skipped" in ffuf                 # needs {wordlist}, cannot auto-fill
    assert not any("ffuf" in c for c in ran)  # never actually ran
    store.close()


def test_auto_run_records_runs_in_coverage(tmp_path):
    svc, store, ran = _svc(tmp_path)
    svc.auto_run("ex.com")
    assert {"subfinder", "katana", "nuclei"} <= store.tools_run_for_target("ex.com")
    store.close()
