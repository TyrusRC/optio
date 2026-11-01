"""The tool catalog — definitions of the tools Optio can run.

A catalog entry names the binary, the lane and flow phase it belongs to, a
command template with ``{placeholder}`` fields the launcher fills from the
target, and the vuln classes it tests (if any). Optio ships a starter catalog
as packaged data; the operator adds their own YAML files on top.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

_FORMATTER = string.Formatter()


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    lane: str
    phase: str
    template: str
    classes: list[str] = field(default_factory=list)
    description: str = ""
    # scope decides whether the host-flow advisor auto-suggests this tool.
    # "web"/"net" = host/URL-targetable (suggested in the flow). "cloud"/"code"/
    # "creds"/"mobile" = a different target type: catalog- and pipeline-runnable,
    # but not auto-suggested against a host.
    scope: str = "web"

    HOST_SCOPES = ("web", "net")

    def host_targetable(self) -> bool:
        return self.scope in self.HOST_SCOPES

    def placeholders(self) -> list[str]:
        """The ``{name}`` fields the template expects."""
        return [fname for _, fname, _, _ in _FORMATTER.parse(self.template) if fname]

    def missing_placeholders(self, values: dict[str, str]) -> list[str]:
        """Template fields not satisfied (or empty) in ``values``, in order."""
        out: list[str] = []
        for name in self.placeholders():
            if name not in out and not values.get(name):
                out.append(name)
        return out

    def render(self, values: dict[str, str]) -> str:
        """The exact command line, placeholders filled from ``values``."""
        return self.template.format(**values)

    def render_partial(self, values: dict[str, str]) -> str:
        """Fill known placeholders; leave unknown ones literal (e.g. ``{wordlist}``)."""
        class _Safe(dict):
            def __missing__(self, key: str) -> str:
                return "{" + key + "}"
        return self.template.format_map(_Safe(values))


def _tools_from_doc(doc: dict) -> list[Tool]:
    out: list[Tool] = []
    for raw in (doc or {}).get("tools", []):
        out.append(Tool(
            name=raw["name"],
            binary=raw.get("binary", raw["name"]),
            lane=raw.get("lane", "misc"),
            phase=raw.get("phase", "recon"),
            template=raw["template"],
            classes=list(raw.get("classes", [])),
            description=raw.get("description", ""),
            scope=raw.get("scope", "web"),
        ))
    return out


def load_catalog(paths: list[Path]) -> list[Tool]:
    """Load and merge catalog YAML files. Later files override earlier names."""
    by_name: dict[str, Tool] = {}
    for path in paths:
        if not path.exists():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for tool in _tools_from_doc(doc):
            by_name[tool.name] = tool
    return list(by_name.values())


def load_default_catalog() -> list[Tool]:
    """The starter catalog shipped as packaged data."""
    text = resources.files("optio.data").joinpath("core.yaml").read_text(encoding="utf-8")
    return _tools_from_doc(yaml.safe_load(text))
