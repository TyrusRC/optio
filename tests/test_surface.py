"""The attack-surface model — assets, edges, and the graph the web UI draws.

An engagement is a graph: a domain has subdomains, a subdomain resolves to
hosts, a host exposes services, a service serves endpoints, and findings hang
off the asset they affect. The store holds that graph; surface_graph() projects
it to nodes+edges for a Wiz-style view. Assets dedupe on (kind, value) so the
same host discovered twice is one node.
"""

from optio.service import OptioService
from optio.store import Store


def _svc(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    return OptioService(s, catalog=[], pipelines=[],
                        ranker=lambda o, t, k: None), s


def test_add_asset_returns_id_and_dedupes(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    a = s.add_asset("ex.com", kind="subdomain", value="api.ex.com")
    again = s.add_asset("ex.com", kind="subdomain", value="api.ex.com")
    assert a == again  # same (kind, value) -> one node
    assert len(s.assets_for_target("ex.com")) == 1


def test_assets_form_a_parent_child_graph(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    dom = s.add_asset("ex.com", "domain", "ex.com")
    sub = s.add_asset("ex.com", "subdomain", "api.ex.com", parent_id=dom)
    rows = {r["value"]: r for r in s.assets_for_target("ex.com")}
    assert rows["api.ex.com"]["parent_id"] == dom
    assert rows["ex.com"]["parent_id"] is None


def test_asset_carries_metadata(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com")
    s.add_asset("ex.com", "service", "api.ex.com:443",
                data={"tls": "TLS1.2", "tech": ["nginx"]})
    row = s.assets_for_target("ex.com")[0]
    assert row["data"]["tls"] == "TLS1.2"


def test_surface_graph_projects_nodes_and_edges(tmp_path):
    svc, store = _svc(tmp_path)
    dom = svc.record_asset("ex.com", "domain", "ex.com")["id"]
    svc.record_asset("ex.com", "subdomain", "api.ex.com", parent_id=dom)
    g = svc.surface_graph("ex.com")
    ids = {n["id"] for n in g["nodes"]}
    assert len(ids) == 2
    assert any(e["source"] == dom for e in g["edges"])  # domain -> subdomain edge
    store.close()


def test_surface_graph_attaches_findings_to_their_endpoint(tmp_path):
    svc, store = _svc(tmp_path)
    svc.record_asset("ex.com", "endpoint", "/invoice/{id}")
    svc.add_finding("ex.com", title="IDOR", endpoint="/invoice/{id}",
                    severity="high", status="confirmed")
    g = svc.surface_graph("ex.com")
    ep = next(n for n in g["nodes"] if n["value"] == "/invoice/{id}")
    assert ep["severity"] == "high"  # node inherits worst finding severity
    assert ep["finding_count"] == 1
    store.close()
