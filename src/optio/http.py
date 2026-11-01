"""A standalone HTTP request runner — Optio's built-in repeater.

A web engagement is mostly send-request / read-response. Without this the
operator drops to ``curl`` and the cockpit stops helping. This sends one request
and captures the response as durable evidence (status, headers, body, timing),
so a finding cites a snapshot that outlives any proxy session.

Stdlib only (``urllib``). Two deliberate choices for a testing tool:

- Redirects are NOT followed by default — a 302 is a finding (open redirect,
  auth gate), so the operator must see it, not the page it points to.
- TLS verification is ON by default; pass ``verify=False`` for the self-signed
  hosts common in labs and staging. The default stays safe; the operator opts
  out per call.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass(frozen=True)
class HttpResponse:
    status: int  # 0 means the request never completed — see .error
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    elapsed_ms: int = 0
    error: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn a 3xx into an HTTPError instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_raw(text: str, scheme: str = "https") -> tuple[str, str, dict[str, str], str]:
    """Parse a raw HTTP request (the Repeater format) into send() arguments.

    Returns ``(method, url, headers, body)``. The URL is built from the request
    line path and the ``Host`` header. ``Host`` stays out of the returned
    headers — urllib sets it from the URL.
    """
    text = text.replace("\r\n", "\n").lstrip("\n")
    if not text.strip():
        raise ValueError("empty request")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"bad request line: {lines[0]!r}")
    method, path = parts[0].upper(), parts[1]

    headers: dict[str, str] = {}
    host = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip(), val.strip()
        if key.lower() == "host":
            host = val
        else:
            headers[key] = val
    if not host:
        raise ValueError("no Host header")
    if path.lower().startswith(("http://", "https://")):
        url = path
    else:
        url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
    return method, url, headers, body


def send(method: str, url: str, headers: dict[str, str] | None = None,
         body: str | bytes | None = None, proxy: str | None = None,
         timeout: float = 30.0, verify: bool = True,
         allow_redirects: bool = False) -> HttpResponse:
    """Send one request and capture the response. Never raises — a transport
    failure comes back as ``status=0`` with ``.error`` set."""
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper())
    for key, val in (headers or {}).items():
        req.add_header(key, val)

    handlers: list[urllib.request.BaseHandler] = []
    if not allow_redirects:
        handlers.append(_NoRedirect())
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)

    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            return _build(resp.status, resp.getheaders(), raw, start)
    except urllib.error.HTTPError as e:  # 3xx (no-redirect) and 4xx/5xx
        raw = e.read() if hasattr(e, "read") else b""
        return _build(e.code, list(e.headers.items()), raw, start)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return HttpResponse(status=0, elapsed_ms=_ms(start), error=str(e))


def _build(status: int, headers, raw: bytes, start: float) -> HttpResponse:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")
    return HttpResponse(status=status, headers=list(headers), body=text, elapsed_ms=_ms(start))


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def raw_template(host: str, path: str = "/") -> str:
    """A starter raw request for the repeater — the operator edits from here."""
    host = host or "TARGET-HOST"
    return (f"GET {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"User-Agent: optio\n"
            f"Accept: */*\n\n")
