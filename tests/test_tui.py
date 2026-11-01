"""Drive the real TUI with Textual's pilot — it must mount and render state."""

import asyncio

from textual.widgets import DataTable

from optio.store import Store
from optio.tui.app import OptioApp


async def _scenario(store):
    app = OptioApp(store=store)
    async with app.run_test() as pilot:
        await pilot.pause()
        dt = app.query_one("#coverage", DataTable)
        assert dt.row_count == len(app.catalog)
        # advisor computed a next action, and a fresh target starts at recon
        assert app._suggestions
        assert app._suggestions[0].phase == "recon"
        # pipelines are loaded and the new bindings exist
        assert any(p.name == "recon-sweep" for p in app.pipelines)
        keys = {b[0] for b in app.BINDINGS}
        assert {"p", "h"} <= keys


def test_app_mounts_and_shows_next_action(tmp_path, monkeypatch):
    monkeypatch.setenv("OPTIO_HOME", str(tmp_path))
    store = Store(tmp_path / "t.db")
    store.add_target("ex.com", tech=["php"])
    asyncio.run(_scenario(store))
    store.close()
