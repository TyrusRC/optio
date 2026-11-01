"""Catalog loading and command rendering."""

import textwrap

from optio.catalog import Tool, load_catalog, load_default_catalog


def test_default_catalog_has_the_starter_tools():
    cat = load_default_catalog()
    names = {t.name for t in cat}
    assert {"subfinder", "httpx", "katana", "gau", "ffuf",
            "nuclei", "sqlmap", "dalfox", "nmap"} <= names


def test_tool_declares_lane_and_phase():
    cat = load_default_catalog()
    sqlmap = next(t for t in cat if t.name == "sqlmap")
    assert sqlmap.phase == "probe"
    assert sqlmap.lane == "web-scan"
    assert "sqli" in sqlmap.classes


def test_load_catalog_from_yaml_file(tmp_path):
    p = tmp_path / "extra.yaml"
    p.write_text(textwrap.dedent("""
        tools:
          - name: mytool
            binary: mytool
            lane: recon
            phase: recon
            template: "mytool {domain}"
            description: custom
    """))
    cat = load_catalog([p])
    assert len(cat) == 1
    assert cat[0].name == "mytool"


def test_render_fills_placeholders():
    t = Tool(name="x", binary="httpx", lane="recon", phase="recon",
             template="httpx -u {url} -d {domain}", classes=[], description="")
    cmd = t.render({"url": "https://ex.com", "domain": "ex.com"})
    assert cmd == "httpx -u https://ex.com -d ex.com"


def test_render_partial_leaves_unknown_placeholders_literal():
    t = Tool(name="x", binary="ffuf", lane="recon", phase="surface",
             template="ffuf -u {url}/FUZZ -w {wordlist}", classes=[], description="")
    cmd = t.render_partial({"url": "https://ex.com"})
    assert cmd == "ffuf -u https://ex.com/FUZZ -w {wordlist}"


def test_render_reports_missing_placeholder():
    t = Tool(name="x", binary="ffuf", lane="recon", phase="surface",
             template="ffuf -u {url}/FUZZ -w {wordlist}", classes=[], description="")
    missing = t.missing_placeholders({"url": "https://ex.com"})
    assert missing == ["wordlist"]
