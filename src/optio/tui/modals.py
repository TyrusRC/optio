"""Small modal screens for the TUI."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static


class PromptModal(ModalScreen[str | None]):
    """Ask for one line of text. Dismisses with the string, or None on cancel."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, title: str, initial: str = "", confirm_label: str = "OK",
                 note: str = "") -> None:
        super().__init__()
        self._title = title
        self._initial = initial
        self._confirm_label = confirm_label
        self._note = note

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-box"):
            yield Label(self._title, id="prompt-title")
            if self._note:
                yield Static(self._note, id="prompt-note")
            yield Input(value=self._initial, id="prompt-input")
            yield Button(self._confirm_label, variant="primary", id="prompt-ok")

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "prompt-ok":
            self.dismiss(self.query_one("#prompt-input", Input).value)

    def action_cancel(self) -> None:
        self.dismiss(None)
