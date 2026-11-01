"""The next-action advisor — a deterministic, findings-first priority ladder.

Mirrors Praetor's flow: confirm leads before scanning more, walk the phases in
order, prioritise probe classes by tech stack, and fall back to a
change-approach nudge when a target is fully covered with nothing found. The
operator always decides; these are ranked hints.
"""

from optio.advisor import suggest
from optio.catalog import load_default_catalog

CAT = load_default_catalog()


def _phase_tools(phase):
    return {t.name for t in CAT if t.phase == phase}


def test_fresh_target_suggests_recon_first():
    out = suggest(CAT, tech=["default"], tools_run=set(), findings=[])
    assert out, "advisor must return at least one suggestion"
    assert out[0].phase == "recon"
    assert out[0].tool in _phase_tools("recon")


def test_recon_done_moves_to_surface():
    out = suggest(CAT, tech=["default"], tools_run=_phase_tools("recon"), findings=[])
    assert out[0].phase == "surface"
    assert out[0].tool in _phase_tools("surface")


def test_suspected_finding_beats_more_scanning():
    findings = [{"vuln_class": "sqli", "endpoint": "/item", "status": "suspected"}]
    out = suggest(CAT, tech=["default"], tools_run=set(), findings=findings)
    top = out[0]
    assert top.tool is None or top.tool == "sqlmap"
    assert "verify" in top.action.lower() or "confirm" in top.action.lower()
    assert "sqli" in (top.action + top.reason).lower()
    assert top.priority == 0


def test_probe_phase_orders_classes_by_tech():
    # php prioritises sqli over xss -> sqlmap suggested ahead of dalfox.
    done = _phase_tools("recon") | _phase_tools("surface") | _phase_tools("scan")
    out = suggest(CAT, tech=["php"], tools_run=done, findings=[])
    probe = [s for s in out if s.phase == "probe"]
    assert probe, "expected probe suggestions once earlier phases are done"
    assert probe[0].tool == "sqlmap"


def test_full_coverage_no_findings_suggests_change_of_approach():
    host_tools = {t.name for t in CAT if t.host_targetable()}
    out = suggest(CAT, tech=["default"], tools_run=host_tools, findings=[])
    assert any(s.tool is None and "approach" in s.action.lower() for s in out)


def test_non_host_tools_are_never_auto_suggested():
    # a fresh target walks recon; cloud/code/creds tools must not appear
    non_host = {t.name for t in CAT if not t.host_targetable()}
    assert "prowler" in non_host and "trufflehog" in non_host
    # run every host tool so the flow is exhausted; still no non-host suggestion
    host_tools = {t.name for t in CAT if t.host_targetable()}
    for run in (set(), host_tools):
        out = suggest(CAT, tech=["php"], tools_run=run, findings=[])
        assert all(s.tool is None or s.tool not in non_host for s in out)


def test_command_rendered_when_target_values_present():
    out = suggest(CAT, tech=["default"], tools_run=set(), findings=[],
                  target_values={"domain": "ex.com", "url": "https://ex.com", "host": "ex.com"})
    top = out[0]
    assert top.command and "ex.com" in top.command
