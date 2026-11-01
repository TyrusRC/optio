"""Static pentest knowledge tables that drive the next-action advisor.

These are generic methodology knowledge, not target data:

- ``TECH_PRIORITIES`` — a tech/framework maps to an ordered list of the vuln
  classes worth testing first on that stack.
- ``PARAM_VULN_MAP`` — a parameter name hints at a likely vuln class.
- ``CLASS_TO_TOOL`` — a vuln class maps to the catalog tool that tests it, when
  Optio ships one. Classes with no tool become a manual-test note.

The flow order and the catalog (each tool declares its phase) carry the rest.
"""

from __future__ import annotations

# Tech stack -> prioritized vulnerability classes (most valuable first).
TECH_PRIORITIES: dict[str, list[str]] = {
    "php": ["sqli", "lfi", "file_upload", "ssti", "command_injection", "xxe", "ssrf"],
    "java": ["deserialization", "xxe", "ssti", "sqli", "ssrf", "path_traversal"],
    "spring": ["deserialization", "ssti", "xxe", "sqli", "ssrf", "path_traversal"],
    "python": ["ssti", "command_injection", "ssrf", "sqli", "path_traversal"],
    "flask": ["ssti", "command_injection", "ssrf", "sqli", "path_traversal"],
    "django": ["ssti", "sqli", "idor", "ssrf", "path_traversal", "xss"],
    "node": ["ssti", "ssrf", "command_injection", "prototype_pollution", "sqli", "xss"],
    "express": ["ssti", "ssrf", "prototype_pollution", "sqli", "xss"],
    "nextjs": ["ssrf", "prototype_pollution", "open_redirect", "xss"],
    "ruby": ["ssti", "command_injection", "sqli", "ssrf", "xss"],
    "rails": ["mass_assignment", "ssti", "sqli", "idor", "ssrf"],
    "laravel": ["sqli", "ssti", "mass_assignment", "path_traversal", "file_upload"],
    "asp.net": ["deserialization", "sqli", "path_traversal", "xxe", "ssrf", "xss"],
    ".net": ["deserialization", "sqli", "path_traversal", "xxe", "ssrf", "xss"],
    "angular": ["xss", "ssti", "prototype_pollution", "cors", "open_redirect"],
    "react": ["xss", "ssrf", "cors", "prototype_pollution", "open_redirect"],
    "vue": ["xss", "ssti", "prototype_pollution", "open_redirect"],
    "wordpress": ["sqli", "xss", "file_upload", "lfi", "auth_bypass", "ssrf"],
    "drupal": ["sqli", "xss", "file_upload", "lfi", "auth_bypass"],
    "graphql": ["graphql", "idor", "sqli", "auth_bypass", "info_disclosure"],
    "api": ["idor", "auth_bypass", "mass_assignment", "sqli", "ssrf"],
    "go": ["ssrf", "ssti", "path_traversal", "auth_bypass"],
    "default": ["xss", "sqli", "ssrf", "idor", "auth_bypass", "ssti", "path_traversal"],
}

# Parameter name -> likely vulnerability class.
PARAM_VULN_MAP: dict[str, str] = {
    "id": "idor", "uid": "idor", "user_id": "idor", "account_id": "idor", "order_id": "idor",
    "search": "xss", "q": "xss", "query": "xss", "name": "xss", "comment": "xss", "message": "xss",
    "url": "ssrf", "redirect": "open_redirect", "next": "open_redirect", "return": "open_redirect",
    "callback": "ssrf", "webhook": "ssrf", "target": "ssrf", "uri": "ssrf",
    "file": "lfi", "path": "lfi", "page": "lfi", "template": "ssti", "include": "lfi",
    "email": "sqli", "username": "sqli", "login": "sqli", "sort": "sqli", "order": "sqli",
    "cmd": "command_injection", "exec": "command_injection", "command": "command_injection",
    "lang": "lfi", "locale": "lfi", "dir": "path_traversal", "folder": "path_traversal",
}

# Vuln class -> catalog tool name that tests it (when Optio ships one).
CLASS_TO_TOOL: dict[str, str] = {
    "sqli": "sqlmap",
    "sql_injection": "sqlmap",
    "xss": "dalfox",
    "command_injection": "commix",
    "rce": "commix",
}

# Infra / recon classes that NO catalog tool covers end-to-end. The old
# tool-list coverage model dropped these entirely — a class with no tool was
# invisible. They are always applicable to a web target and are tested manually
# (or with a tool the operator wires in), so they appear in the coverage board
# as untested until proven, never silently missed.
INFRA_CLASSES: dict[str, str] = {
    "subdomain_takeover": "Check every CNAME/alias for a dangling pointer to an "
                          "unclaimed service (S3, GitHub Pages, Heroku, Azure, ...).",
    "tls_ssl": "Review TLS: protocol versions, weak ciphers, cert validity/chain, "
               "HSTS. (testssl.sh / sslscan / tlsx).",
    "dns": "Check DNS: zone transfer (AXFR), wildcard, dangling records, SPF/DMARC.",
    "security_headers": "Review response headers: CSP, X-Frame-Options, HSTS, "
                        "cookie flags. Report only chained to impact.",
}

# How each app/authz/auth vuln class is tested when it has no dedicated tool —
# a short manual instruction so the class is actionable, not a bare name.
MANUAL_ACTIONS: dict[str, str] = {
    "idor": "Swap an object id/UUID for another user's and replay with your session.",
    "bola": "Same as IDOR at the object level across roles (test_auth_matrix-style).",
    "auth_bypass": "Force-browse protected routes; tamper role/JWT claims; check gates.",
    "ssrf": "Point a URL/callback param at an internal/metadata address; watch for OOB.",
    "ssti": "Inject a template expression (e.g. {{7*7}}) into reflected inputs.",
    "xxe": "Submit XML with an external entity; watch for file read / OOB.",
    "path_traversal": "Walk ../ sequences in file/path params; read a known file.",
    "lfi": "Include a local file via a path/page param; confirm contents.",
    "open_redirect": "Set a redirect/next param to an external host; confirm the 30x.",
    "prototype_pollution": "Inject __proto__/constructor keys; check polluted behaviour.",
    "mass_assignment": "Add privileged fields (role, is_admin) to a write body.",
    "deserialization": "Submit a crafted serialized object to a sink that deserializes.",
    "graphql": "Introspect the schema; test field authz, batching, injection.",
    "race_condition": "Fire the state-changing request concurrently; check for TOCTOU.",
    "business_logic": "Reorder/skip/replay steps; tamper price/quantity/state.",
    "info_disclosure": "Collect leaked paths/versions/errors; escalate, do not file alone.",
}


def applicable_classes(techs: list[str]) -> list[str]:
    """Every vuln class worth tracking for this target: the tech-prioritised app
    classes PLUS the infra classes that are always in scope for a web target.

    The infra classes are the ones the tool-list model missed. They come last
    (recon output, Rule 29) but they are never dropped."""
    out = classes_for_tech(techs)
    for cls in INFRA_CLASSES:
        if cls not in out:
            out.append(cls)
    return out


def action_for_class(vuln_class: str) -> tuple[str | None, str]:
    """Return ``(tool, action_text)`` for a class: the catalog tool if one tests
    it, else None and a manual instruction. Never returns an empty action."""
    tool = CLASS_TO_TOOL.get(vuln_class)
    if tool:
        return tool, f"Run {tool} against the parameter."
    if vuln_class in INFRA_CLASSES:
        return None, INFRA_CLASSES[vuln_class]
    if vuln_class in MANUAL_ACTIONS:
        return None, MANUAL_ACTIONS[vuln_class]
    return None, f"Test {vuln_class} manually against the relevant inputs."


# Recon-phase tools, ordered by value — active resolve / port-service discovery
# first, passive subdomain/OSINT enumeration last. The advisor sorts the open
# recon tools by this instead of catalog position, so "run subfinder" is no
# longer the default just because it is first in the YAML. Tools absent here
# sort after the listed ones.
RECON_ORDER: list[str] = [
    "groma", "naabu", "nmap", "masscan",   # ports + services (high signal)
    "dnsx", "tlsx", "asnmap", "cdncheck",  # resolve / TLS / network mapping
    "subfinder", "amass", "assetfinder", "chaos", "shuffledns", "alterx",
    "dnsgen", "uncover", "theharvester",   # passive subdomain / OSINT
]


def recon_rank(tool_name: str) -> int:
    """Value rank of a recon tool; unknown tools sort after the known ones."""
    try:
        return RECON_ORDER.index(tool_name)
    except ValueError:
        return len(RECON_ORDER)


def classes_for_tech(techs: list[str]) -> list[str]:
    """Ordered, de-duplicated vuln classes for a set of detected techs."""
    out: list[str] = []
    seen: set[str] = set()
    for tech in techs or ["default"]:
        for cls in TECH_PRIORITIES.get(tech.lower().strip(), []):
            if cls not in seen:
                seen.add(cls)
                out.append(cls)
    if not out:
        out = list(TECH_PRIORITIES["default"])
    return out
