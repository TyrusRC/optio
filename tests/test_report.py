"""The report renderer — findings become a deliverable.

A tracked finding is not a deliverable; a report is. This renders findings to
markdown the way a pentest report reads: an executive summary (risk posture, no
activity counts) then per-finding detail with evidence. A field that was never
captured prints an explicit marker, so the gap is visible, not invented.
"""

from optio import report


CONFIRMED = {
    "id": 1, "title": "IDOR on /invoice", "vuln_class": "idor",
    "endpoint": "/invoice/{id}", "severity": "high", "status": "confirmed",
    "impact": "Any authenticated user reads another user's invoice (PII).",
    "remediation": "Enforce object ownership server-side.",
    "cwe": "CWE-639", "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N",
    "reproduction": "1. Log in. 2. GET /invoice/1001.",
    "evidence_request_id": 7, "notes": "",
}
SUSPECTED = {**CONFIRMED, "id": 2, "title": "Maybe XSS", "status": "suspected",
             "severity": "medium"}


def _lookup(rid):
    if rid == 7:
        return {"method": "GET", "url": "https://ex.com/invoice/1001",
                "status": 200, "resp_body": "other user's invoice", "elapsed_ms": 30}
    return None


def test_report_has_title_and_executive_summary():
    md = report.render_markdown("ex.com", [CONFIRMED])
    assert "ex.com" in md
    assert "Executive Summary" in md
    assert "HIGH" in md.upper()


def test_client_report_includes_only_confirmed():
    md = report.render_markdown("ex.com", [CONFIRMED, SUSPECTED], audience="client")
    assert "IDOR on /invoice" in md
    assert "Maybe XSS" not in md


def test_finding_renders_impact_remediation_and_evidence():
    md = report.render_markdown("ex.com", [CONFIRMED], request_lookup=_lookup)
    assert "Any authenticated user reads" in md
    assert "Enforce object ownership" in md
    assert "CWE-639" in md
    assert "GET https://ex.com/invoice/1001" in md  # evidence snapshot, not an index
    assert "200" in md


def test_missing_field_prints_explicit_marker():
    bare = {"id": 3, "title": "Thin finding", "severity": "high", "status": "confirmed",
            "endpoint": "/x", "impact": "", "remediation": "", "cwe": "", "cvss": "",
            "reproduction": "", "evidence_request_id": None, "vuln_class": "idor", "notes": ""}
    md = report.render_markdown("ex.com", [bare])
    assert "NOT SUPPLIED" in md.upper()


def test_report_has_no_activity_counts():
    md = report.render_markdown("ex.com", [CONFIRMED], request_lookup=_lookup).lower()
    for banned in ("payloads sent", "requests sent", "tests run", "endpoints scanned"):
        assert banned not in md


def test_empty_report_states_no_confirmed_findings():
    md = report.render_markdown("ex.com", [SUSPECTED], audience="client")
    assert "no confirmed findings" in md.lower()
