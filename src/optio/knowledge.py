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
    "xss": "dalfox",
}


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
