"""API routes that feed the web UI: surface graph, coverage board, assets."""

from optio.api import _route
from optio.service import OptioService
from optio.store import Store


def _svc(tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_target("ex.com", tech=["php"])
    return OptioService(s, catalog=[], pipelines=[], ranker=lambda o, t, k: None), s


def test_surface_route_returns_graph(tmp_path):
    svc, store = _svc(tmp_path)
    dom = svc.record_asset("ex.com", "domain", "ex.com")["id"]
    svc.record_asset("ex.com", "subdomain", "api.ex.com", parent_id=dom)
    g = _route(svc, "GET", "/targets/ex.com/surface", {})
    assert len(g["nodes"]) == 2 and len(g["edges"]) == 1
    store.close()


def test_coverage_classes_route(tmp_path):
    svc, store = _svc(tmp_path)
    svc.record_class_coverage("ex.com", "sqli", "finding")
    board = {c["vuln_class"]: c for c in _route(svc, "GET", "/targets/ex.com/coverage-classes", {})}
    assert board["sqli"]["status"] == "finding"
    assert "subdomain_takeover" in board  # infra class present
    store.close()


def test_post_asset_route(tmp_path):
    svc, store = _svc(tmp_path)
    out = _route(svc, "POST", "/targets/ex.com/assets",
                 {"kind": "endpoint", "value": "/login"})
    assert out["id"]
    rows = _route(svc, "GET", "/targets/ex.com/assets", {})
    assert rows[0]["value"] == "/login"
    store.close()


def test_post_coverage_route(tmp_path):
    svc, store = _svc(tmp_path)
    _route(svc, "POST", "/targets/ex.com/coverage-classes",
           {"vuln_class": "tls_ssl", "status": "tested", "note": "TLS1.2 only, ok"})
    assert store.class_coverage_map("ex.com")["tls_ssl"] == "tested"
    store.close()
