"""Coverage is measured by vuln CLASS, not by which tools ran.

The old model asked "did every tool run?" — so a class with no catalog tool
(subdomain takeover, TLS/SSL config, DNS, security headers) was invisible and
silently missed. This model lists every applicable class, tracks each as
tested/untested, and points at a tool OR a manual note. Nothing is missed just
because Optio ships no scanner for it.
"""

from optio.advisor import class_coverage
from optio.knowledge import applicable_classes


def test_infra_classes_are_always_applicable_and_never_missed():
    classes = applicable_classes(["php"])
    for infra in ("subdomain_takeover", "tls_ssl", "dns", "security_headers"):
        assert infra in classes  # the tool-list model dropped these


def test_tech_classes_are_included():
    classes = applicable_classes(["php"])
    assert "sqli" in classes and "lfi" in classes


def test_class_coverage_marks_untested_until_recorded():
    cov = class_coverage(["php"], covered={})
    by = {c["vuln_class"]: c for c in cov}
    assert by["sqli"]["status"] == "untested"
    assert by["tls_ssl"]["status"] == "untested"


def test_class_coverage_reflects_recorded_status():
    cov = class_coverage(["php"], covered={"sqli": "tested", "tls_ssl": "finding"})
    by = {c["vuln_class"]: c for c in cov}
    assert by["sqli"]["status"] == "tested"
    assert by["tls_ssl"]["status"] == "finding"


def test_classless_class_gets_a_manual_action_not_a_tool():
    cov = class_coverage(["php"], covered={})
    takeover = next(c for c in cov if c["vuln_class"] == "subdomain_takeover")
    assert takeover["tool"] is None
    assert takeover["action"]  # a manual instruction, not an empty string
    sqli = next(c for c in cov if c["vuln_class"] == "sqli")
    assert sqli["tool"] == "sqlmap"
