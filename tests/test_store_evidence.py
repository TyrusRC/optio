"""Durable evidence in the store — captured requests and richer findings.

The engagement that drove this lost evidence when a proxy restarted and its
indices went stale. Optio snapshots the request/response into its own store, so
a finding cites a row that never disappears. Findings also carry the fields a
report renders (impact/remediation/cwe/cvss), not just a title.
"""

from optio.store import Store


def _store(tmp_path):
    return Store(tmp_path / "t.db")


def test_record_and_get_request_roundtrips(tmp_path):
    s = _store(tmp_path)
    rid = s.record_request(
        "ex.com", method="POST", url="https://ex.com/login",
        req_headers={"Content-Type": "application/json"}, req_body='{"u":1}',
        status=200, resp_headers={"Server": "nginx"}, resp_body="ok", elapsed_ms=42)
    got = s.get_request(rid)
    assert got["method"] == "POST"
    assert got["url"] == "https://ex.com/login"
    assert got["req_headers"]["Content-Type"] == "application/json"
    assert got["status"] == 200
    assert got["resp_body"] == "ok"
    assert got["elapsed_ms"] == 42
    s.close()


def test_requests_for_target_lists_newest_first(tmp_path):
    s = _store(tmp_path)
    s.record_request("ex.com", "GET", "https://ex.com/a", {}, "", 200, {}, "", 1)
    second = s.record_request("ex.com", "GET", "https://ex.com/b", {}, "", 200, {}, "", 1)
    rows = s.requests_for_target("ex.com")
    assert rows[0]["id"] == second
    assert len(rows) == 2
    s.close()


def test_finding_carries_report_fields(tmp_path):
    s = _store(tmp_path)
    fid = s.add_finding(
        "ex.com", title="IDOR on /invoice", vuln_class="idor",
        endpoint="/invoice/{id}", severity="high", status="confirmed",
        impact="Any user reads another user's invoice (PII).",
        remediation="Enforce object ownership on the server.",
        cwe="CWE-639", cvss="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N",
        evidence_request_id=7, reproduction="1. Log in. 2. GET /invoice/1001.")
    f = s.findings_for_target("ex.com")[0]
    assert f["id"] == fid
    assert f["impact"].startswith("Any user")
    assert f["cwe"] == "CWE-639"
    assert f["evidence_request_id"] == 7
    assert "VC:H" in f["cvss"]
    s.close()


def test_old_findings_table_is_migrated(tmp_path):
    """A store created before the new columns still opens and gains them."""
    import sqlite3

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,"
        " title TEXT NOT NULL, vuln_class TEXT DEFAULT '', endpoint TEXT DEFAULT '',"
        " severity TEXT DEFAULT 'low', status TEXT DEFAULT 'suspected', notes TEXT DEFAULT '',"
        " created_at REAL NOT NULL);")
    con.execute("INSERT INTO findings(target,title,created_at) VALUES ('ex.com','old one',1.0)")
    con.commit()
    con.close()

    s = Store(db)  # must not raise, and must add the columns
    fid = s.add_finding("ex.com", title="new one", impact="real impact")
    rows = s.findings_for_target("ex.com")
    assert {r["title"] for r in rows} == {"old one", "new one"}
    assert next(r for r in rows if r["id"] == fid)["impact"] == "real impact"
    s.close()
