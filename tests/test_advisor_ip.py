"""The advisor must respect the target type.

A bare IP has no domain to enumerate, so suggesting subdomain tools (subfinder,
amass, gau) against it is noise — the bug the real engagement hit. Host/URL
tools (nmap, httpx, nuclei) still apply to an IP and must stay.
"""

from optio.advisor import suggest
from optio.catalog import Tool
from optio.context import is_ip, target_values

CATALOG = [
    Tool(name="subfinder", binary="subfinder", lane="recon", phase="recon",
         template="subfinder -d {domain}", description="subdomains", scope="web"),
    Tool(name="httpx", binary="httpx", lane="recon", phase="surface",
         template="httpx -u {url}", description="probe", scope="web"),
    Tool(name="nmap", binary="nmap", lane="network", phase="recon",
         template="nmap -sV {host}", description="ports", scope="net"),
]


def test_is_ip_distinguishes_ip_from_domain():
    assert is_ip("192.168.1.136")
    assert is_ip("10.0.0.1:8080")
    assert not is_ip("example.com")
    assert not is_ip("sub.example.com")


def test_ip_target_skips_domain_only_tools():
    tvals = target_values("192.168.1.136")
    actions = suggest(CATALOG, ["default"], set(), [], tvals)
    tools = {s.tool for s in actions if s.tool}
    assert "subfinder" not in tools        # domain enumeration on an IP is noise
    assert {"nmap", "httpx"} & tools       # host/url tools still apply


def test_domain_target_keeps_domain_tools():
    tvals = target_values("example.com")
    actions = suggest(CATALOG, ["default"], set(), [], tvals)
    tools = {s.tool for s in actions if s.tool}
    assert "subfinder" in tools
