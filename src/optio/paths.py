"""XDG base-directory paths for Optio.

Config and the tool catalog live in the config dir; the SQLite state store in
the data dir; captured raw tool output in the cache dir. Each honours its XDG
environment variable and falls back to the spec default. ``OPTIO_HOME``
overrides all three at once (useful for tests and throwaway runs).
"""

from __future__ import annotations

import os
import re
from pathlib import Path


def _base(xdg_var: str, default_rel: str) -> Path:
    home_override = os.environ.get("OPTIO_HOME")
    if home_override:
        return Path(home_override)
    xdg = os.environ.get(xdg_var)
    root = Path(xdg) if xdg else Path.home() / default_rel
    return root / "optio"


def config_dir() -> Path:
    return _base("XDG_CONFIG_HOME", ".config")


def data_dir() -> Path:
    return _base("XDG_DATA_HOME", ".local/share")


def cache_dir() -> Path:
    return _base("XDG_CACHE_HOME", ".cache")


def db_path() -> Path:
    """Path to the SQLite state store."""
    return data_dir() / "optio.db"


def user_catalog_dir() -> Path:
    """Where the operator drops their own catalog YAML files."""
    return config_dir() / "catalog"


def artifacts_dir(name: str) -> Path:
    """Per-target working directory for tool subprocesses. Tools run with this
    as their CWD so reports they auto-save (nikto's JSON, vigil's report dir,
    ...) land here instead of in the operator's CWD or the repo."""
    slug = re.sub(r"[^\w.-]+", "_", name).strip("_") or "target"
    d = data_dir() / "artifacts" / slug
    d.mkdir(parents=True, exist_ok=True)
    return d
