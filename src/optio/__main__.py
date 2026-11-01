"""Entry point — launch the Optio web UI.

``uv run optio`` serves the attack-surface cockpit on loopback and opens the
browser. It accepts the same flags as the server (``--host``, ``--port``,
``--no-browser``).
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> None:
    from optio.web import serve_web
    serve_web(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    main()
