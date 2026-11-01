"""Coverage persistence + the service board, and the recon-ordering fix."""

from optio.advisor import suggest
from optio.catalog import Tool
from optio.context import target_values
from optio.service import OptioService
from optio.store import Store


def test_record_and_read_class_coverage(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    s.record_coverage("ex.com", "sqli", "tested", note="no injection on id")
    s.record_coverage("ex.com", "sqli", "finding")  # upsert, latest wins
    assert s.class_coverage_map("ex.com") == {"sqli": "finding"}
    s.close()


def test_service_board_merges_recorded_with_applicable(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com", tech=["php"])
    svc = OptioService(s, catalog=[], pipelines=[], ranker=lambda o, t, k: None)
    svc.record_class_coverage("ex.com", "sqli", "finding")
    board = {c["vuln_class"]: c for c in svc.coverage_board("ex.com")}
    assert board["sqli"]["status"] == "finding"
    assert board["tls_ssl"]["status"] == "untested"   # applicable, not yet tested
    s.close()


# ── recon ordering: subfinder must not win by catalog position ───────────────
RECON_CATALOG = [
    Tool(name="subfinder", binary="subfinder", lane="recon", phase="recon",
         template="subfinder -d {domain}", description="passive subs", scope="web"),
    Tool(name="dnsx", binary="dnsx", lane="recon", phase="recon",
         template="dnsx -d {domain}", description="resolve", scope="web"),
    Tool(name="groma", binary="groma", lane="network", phase="recon",
         template="groma scan {host}", description="ports", scope="net"),
]


def test_recon_is_value_ordered_not_catalog_ordered():
    tvals = target_values("ex.com")
    actions = [s for s in suggest(RECON_CATALOG, ["default"], set(), [], tvals) if s.tool]
    assert actions[0].tool != "subfinder"  # position no longer decides
    # passive subdomain enum ranks below active resolve/port discovery
    order = [s.tool for s in actions]
    assert order.index("subfinder") > order.index("dnsx")
    assert order.index("subfinder") > order.index("groma")
