"""Entry point — launch the Optio TUI."""

from __future__ import annotations


def main() -> None:
    from optio.tui.app import OptioApp
    OptioApp().run()


if __name__ == "__main__":
    main()
