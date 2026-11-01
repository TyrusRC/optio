"""Derive command-template values from a target name.

A target is stored as a host (with an optional scheme/port/path the operator may
have pasted). The launcher needs the bare domain, a usable URL, and a host[:port]
to fill ``{domain}`` / ``{url}`` / ``{host}`` placeholders.
"""

from __future__ import annotations

import ipaddress
import re


def is_ip(host: str) -> bool:
    """True when ``host`` (optionally ``host:port``) is a bare IP address.

    An IP has no domain to enumerate, so the advisor skips subdomain tools for
    it. A hostname — even one that looks numeric-ish — is not an IP.
    """
    bare = (host or "").strip().split(":", 1)[0]
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        return False


def target_values(name: str) -> dict[str, str]:
    raw = name.strip()
    scheme = "https"
    m = re.match(r"^([a-z][a-z0-9+.-]*)://(.*)$", raw, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        raw = m.group(2)
    authority = re.split(r"[/?#]", raw, maxsplit=1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    host = authority  # may include :port
    domain = host.split(":", 1)[0]
    return {"domain": domain, "host": host, "url": f"{scheme}://{host}"}
