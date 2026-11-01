"""The local state store (SQLite).

Holds everything Optio tracks for the operator: targets, the coverage ledger
(which tool ran against which target, when, with what result), flag memory (the
last-used command per target+tool), and findings. One file, keyed by target, so
the operator's habits follow them across engagements.

SQLite is the right shape here: the ledger is append-heavy and queried ("did
tool X run against target Y?"), and a single file avoids the rewrite-races of a
JSON blob.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    name          TEXT PRIMARY KEY,
    tech          TEXT NOT NULL DEFAULT '[]',
    notes         TEXT NOT NULL DEFAULT '',
    proxy         TEXT NOT NULL DEFAULT '',
    artifacts_dir TEXT NOT NULL DEFAULT '',
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    tool       TEXT NOT NULL,
    args       TEXT NOT NULL,
    exit_code  INTEGER,
    summary    TEXT NOT NULL DEFAULT '',
    ran_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_target_tool ON runs(target, tool);
CREATE TABLE IF NOT EXISTS flags (
    target TEXT NOT NULL,
    tool   TEXT NOT NULL,
    args   TEXT NOT NULL,
    PRIMARY KEY (target, tool)
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    title      TEXT NOT NULL,
    vuln_class TEXT NOT NULL DEFAULT '',
    endpoint   TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT 'low',
    status     TEXT NOT NULL DEFAULT 'suspected',
    notes      TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
"""

# Worst-first ordering for the findings board.
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Store:
    def __init__(self, db_path: Path | str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path))
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    # ── targets ─────────────────────────────────────────────────────────────
    def add_target(self, name: str, tech: list[str] | None = None, notes: str = "",
                   proxy: str = "", artifacts_dir: str = "") -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO targets(name, tech, notes, proxy, artifacts_dir, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (name, json.dumps(tech or []), notes, proxy, artifacts_dir, time.time()),
        )
        self._db.commit()

    def get_target(self, name: str) -> dict | None:
        row = self._db.execute("SELECT * FROM targets WHERE name=?", (name,)).fetchone()
        return self._target_row(row) if row else None

    def list_targets(self) -> list[dict]:
        rows = self._db.execute("SELECT * FROM targets ORDER BY created_at").fetchall()
        return [self._target_row(r) for r in rows]

    @staticmethod
    def _target_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["tech"] = json.loads(d["tech"])
        return d

    # ── coverage ledger ─────────────────────────────────────────────────────
    def record_run(self, target: str, tool: str, args: str,
                   exit_code: int | None = None, summary: str = "") -> int:
        cur = self._db.execute(
            "INSERT INTO runs(target, tool, args, exit_code, summary, ran_at)"
            " VALUES (?,?,?,?,?,?)",
            (target, tool, args, exit_code, summary, time.time()),
        )
        self._db.commit()
        return cur.lastrowid

    def tools_run_for_target(self, target: str) -> set[str]:
        rows = self._db.execute(
            "SELECT DISTINCT tool FROM runs WHERE target=?", (target,)).fetchall()
        return {r["tool"] for r in rows}

    def last_run(self, target: str, tool: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM runs WHERE target=? AND tool=? ORDER BY ran_at DESC, id DESC LIMIT 1",
            (target, tool)).fetchone()
        return dict(row) if row else None

    def runs_for_target(self, target: str, limit: int = 50) -> list[dict]:
        rows = self._db.execute(
            "SELECT * FROM runs WHERE target=? ORDER BY ran_at DESC, id DESC LIMIT ?",
            (target, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── flag memory ─────────────────────────────────────────────────────────
    def save_flags(self, target: str, tool: str, args: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO flags(target, tool, args) VALUES (?,?,?)",
            (target, tool, args))
        self._db.commit()

    def get_flags(self, target: str, tool: str) -> str | None:
        row = self._db.execute(
            "SELECT args FROM flags WHERE target=? AND tool=?", (target, tool)).fetchone()
        return row["args"] if row else None

    # ── findings ────────────────────────────────────────────────────────────
    def add_finding(self, target: str, title: str, vuln_class: str = "", endpoint: str = "",
                    severity: str = "low", status: str = "suspected", notes: str = "") -> int:
        cur = self._db.execute(
            "INSERT INTO findings(target, title, vuln_class, endpoint, severity, status, notes, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (target, title, vuln_class, endpoint, severity, status, notes, time.time()))
        self._db.commit()
        return cur.lastrowid

    def findings_for_target(self, target: str) -> list[dict]:
        rows = self._db.execute("SELECT * FROM findings WHERE target=?", (target,)).fetchall()
        findings = [dict(r) for r in rows]
        findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 9), f["created_at"]))
        return findings

    def set_finding_status(self, finding_id: int, status: str) -> None:
        self._db.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self._db.commit()
