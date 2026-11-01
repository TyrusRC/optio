"""The local SQLite store — targets, coverage ledger, flag memory, findings."""

import pytest

from optio.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


def test_add_and_get_target_round_trip(store):
    store.add_target("ex.com", tech=["php", "wordpress"], notes="scope A")
    t = store.get_target("ex.com")
    assert t["name"] == "ex.com"
    assert t["tech"] == ["php", "wordpress"]
    assert t["notes"] == "scope A"


def test_list_targets(store):
    store.add_target("a.com")
    store.add_target("b.com")
    assert {t["name"] for t in store.list_targets()} == {"a.com", "b.com"}


def test_new_target_has_no_tools_run(store):
    store.add_target("ex.com")
    assert store.tools_run_for_target("ex.com") == set()


def test_record_run_marks_tool_run(store):
    store.add_target("ex.com")
    store.record_run("ex.com", "nuclei", "nuclei -u https://ex.com", exit_code=0, summary="3 hits")
    assert "nuclei" in store.tools_run_for_target("ex.com")


def test_last_run_returns_most_recent(store):
    store.add_target("ex.com")
    store.record_run("ex.com", "ffuf", "ffuf v1", exit_code=0, summary="old")
    store.record_run("ex.com", "ffuf", "ffuf v2", exit_code=0, summary="new")
    last = store.last_run("ex.com", "ffuf")
    assert last["summary"] == "new"
    assert last["args"] == "ffuf v2"


def test_flag_memory_round_trip_and_overwrite(store):
    store.add_target("ex.com")
    store.save_flags("ex.com", "sqlmap", "sqlmap -u X --level 1")
    assert store.get_flags("ex.com", "sqlmap") == "sqlmap -u X --level 1"
    store.save_flags("ex.com", "sqlmap", "sqlmap -u X --level 5")
    assert store.get_flags("ex.com", "sqlmap") == "sqlmap -u X --level 5"


def test_flag_memory_missing_returns_none(store):
    store.add_target("ex.com")
    assert store.get_flags("ex.com", "sqlmap") is None


def test_findings_lifecycle(store):
    store.add_target("ex.com")
    fid = store.add_finding("ex.com", title="SQLi in id", vuln_class="sqli",
                            endpoint="/item", severity="high")
    findings = store.findings_for_target("ex.com")
    assert len(findings) == 1
    assert findings[0]["status"] == "suspected"
    store.set_finding_status(fid, "confirmed")
    assert store.findings_for_target("ex.com")[0]["status"] == "confirmed"


def test_store_persists_across_reopen(tmp_path):
    p = tmp_path / "t.db"
    s1 = Store(p)
    s1.add_target("ex.com", tech=["node"])
    s1.close()
    s2 = Store(p)
    assert s2.get_target("ex.com")["tech"] == ["node"]
    s2.close()
