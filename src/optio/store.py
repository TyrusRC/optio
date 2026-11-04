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
import threading
import time
from pathlib import Path

# The statuses a finding may hold. 'suspected' is the default lead; only
# 'confirmed' reaches the client report (see report.py). set_finding_status
# validates against this set so a bad API payload can't write garbage.
FINDING_STATUSES = ("suspected", "confirmed", "false_positive", "fixed")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    name          TEXT PRIMARY KEY,
    tech          TEXT NOT NULL DEFAULT '[]',
    notes         TEXT NOT NULL DEFAULT '',
    proxy         TEXT NOT NULL DEFAULT '',
    artifacts_dir TEXT NOT NULL DEFAULT '',
    config        TEXT NOT NULL DEFAULT '{}',
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
    impact              TEXT NOT NULL DEFAULT '',
    remediation         TEXT NOT NULL DEFAULT '',
    cwe                 TEXT NOT NULL DEFAULT '',
    cvss                TEXT NOT NULL DEFAULT '',
    reproduction        TEXT NOT NULL DEFAULT '',
    evidence_request_id INTEGER,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    method       TEXT NOT NULL,
    url          TEXT NOT NULL,
    req_headers  TEXT NOT NULL DEFAULT '{}',
    req_body     TEXT NOT NULL DEFAULT '',
    status       INTEGER NOT NULL DEFAULT 0,
    resp_headers TEXT NOT NULL DEFAULT '{}',
    resp_body    TEXT NOT NULL DEFAULT '',
    elapsed_ms   INTEGER NOT NULL DEFAULT 0,
    sent_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_target ON requests(target);
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    parent_id  INTEGER,
    data       TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    UNIQUE (target, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target);
CREATE TABLE IF NOT EXISTS coverage (
    target     TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'untested',
    note       TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL,
    PRIMARY KEY (target, vuln_class)
);
"""

# Columns added to `findings` after the first release. Each is applied to an
# existing table on open, so a store from an older Optio keeps working.
_FINDING_ADDED_COLUMNS = {
    "impact": "TEXT NOT NULL DEFAULT ''",
    "remediation": "TEXT NOT NULL DEFAULT ''",
    "cwe": "TEXT NOT NULL DEFAULT ''",
    "cvss": "TEXT NOT NULL DEFAULT ''",
    "reproduction": "TEXT NOT NULL DEFAULT ''",
    "evidence_request_id": "INTEGER",
}

# Worst-first ordering for the findings board.
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Store:
    def __init__(self, db_path: Path | str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a lock: the HTTP API serves each request on
        # its own thread, so the connection is shared and all access serialised.
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._migrate()
            self._db.commit()

    def _migrate(self) -> None:
        """Add columns that newer releases expect to pre-existing tables."""
        have = {r["name"] for r in self._db.execute("PRAGMA table_info(findings)")}
        for col, decl in _FINDING_ADDED_COLUMNS.items():
            if col not in have:
                self._db.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
        tcols = {r["name"] for r in self._db.execute("PRAGMA table_info(targets)")}
        if "config" not in tcols:
            self._db.execute("ALTER TABLE targets ADD COLUMN config TEXT NOT NULL DEFAULT '{}'")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ── targets ─────────────────────────────────────────────────────────────
    def add_target(self, name: str, tech: list[str] | None = None, notes: str = "",
                   proxy: str = "", artifacts_dir: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO targets(name, tech, notes, proxy, artifacts_dir, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (name, json.dumps(tech or []), notes, proxy, artifacts_dir, time.time()),
            )
            self._db.commit()

    def get_target(self, name: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM targets WHERE name=?", (name,)).fetchone()
        return self._target_row(row) if row else None

    def list_targets(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM targets ORDER BY created_at").fetchall()
        return [self._target_row(r) for r in rows]

    def set_config(self, name: str, config: dict) -> None:
        """Set per-target config (e.g. ``{headers: {...}, user_agent: "..."}``)."""
        with self._lock:
            self._db.execute("UPDATE targets SET config=? WHERE name=?",
                             (json.dumps(config or {}), name))
            self._db.commit()

    def set_proxy(self, name: str, proxy: str) -> None:
        """Set the per-target proxy — applied to both tool subprocesses (via
        HTTP(S)_PROXY) and the request runner, so all traffic can route through
        an intercepting proxy like Burp."""
        with self._lock:
            self._db.execute("UPDATE targets SET proxy=? WHERE name=?", (proxy or "", name))
            self._db.commit()

    @staticmethod
    def _target_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["tech"] = json.loads(d["tech"])
        d["config"] = json.loads(d["config"] or "{}")
        return d

    # ── coverage ledger ─────────────────────────────────────────────────────
    def record_run(self, target: str, tool: str, args: str,
                   exit_code: int | None = None, summary: str = "") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO runs(target, tool, args, exit_code, summary, ran_at)"
                " VALUES (?,?,?,?,?,?)",
                (target, tool, args, exit_code, summary, time.time()),
            )
            self._db.commit()
            return cur.lastrowid

    def tools_run_for_target(self, target: str) -> set[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT tool FROM runs WHERE target=?", (target,)).fetchall()
        return {r["tool"] for r in rows}

    def last_run(self, target: str, tool: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM runs WHERE target=? AND tool=? ORDER BY ran_at DESC, id DESC LIMIT 1",
                (target, tool)).fetchone()
        return dict(row) if row else None

    def runs_for_target(self, target: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM runs WHERE target=? ORDER BY ran_at DESC, id DESC LIMIT ?",
                (target, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── flag memory ─────────────────────────────────────────────────────────
    def save_flags(self, target: str, tool: str, args: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO flags(target, tool, args) VALUES (?,?,?)",
                (target, tool, args))
            self._db.commit()

    def get_flags(self, target: str, tool: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT args FROM flags WHERE target=? AND tool=?", (target, tool)).fetchone()
        return row["args"] if row else None

    # ── findings ────────────────────────────────────────────────────────────
    def add_finding(self, target: str, title: str, vuln_class: str = "", endpoint: str = "",
                    severity: str = "low", status: str = "suspected", notes: str = "",
                    impact: str = "", remediation: str = "", cwe: str = "", cvss: str = "",
                    reproduction: str = "", evidence_request_id: int | None = None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO findings(target, title, vuln_class, endpoint, severity, status, notes,"
                " impact, remediation, cwe, cvss, reproduction, evidence_request_id, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target, title, vuln_class, endpoint, severity, status, notes,
                 impact, remediation, cwe, cvss, reproduction, evidence_request_id, time.time()))
            self._db.commit()
            return cur.lastrowid

    def findings_for_target(self, target: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM findings WHERE target=?", (target,)).fetchall()
        findings = [dict(r) for r in rows]
        findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 9), f["created_at"]))
        return findings

    def set_finding_status(self, finding_id: int, status: str) -> None:
        if status not in FINDING_STATUSES:
            raise ValueError(
                f"invalid status {status!r}; expected one of {', '.join(FINDING_STATUSES)}")
        with self._lock:
            cur = self._db.execute(
                "UPDATE findings SET status=? WHERE id=?", (status, finding_id))
            self._db.commit()
            if cur.rowcount == 0:
                raise KeyError(f"no finding {finding_id}")

    # ── captured requests (durable evidence) ─────────────────────────────────
    def record_request(self, target: str, method: str, url: str,
                       req_headers: dict | None = None, req_body: str = "",
                       status: int = 0, resp_headers: dict | None = None,
                       resp_body: str = "", elapsed_ms: int = 0) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO requests(target, method, url, req_headers, req_body, status,"
                " resp_headers, resp_body, elapsed_ms, sent_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (target, method, url, json.dumps(req_headers or {}), req_body, status,
                 json.dumps(resp_headers or {}), resp_body, elapsed_ms, time.time()))
            self._db.commit()
            return cur.lastrowid

    def get_request(self, request_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        return self._request_row(row) if row else None

    def requests_for_target(self, target: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM requests WHERE target=? ORDER BY sent_at DESC, id DESC LIMIT ?",
                (target, limit)).fetchall()
        return [self._request_row(r) for r in rows]

    @staticmethod
    def _request_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["req_headers"] = json.loads(d["req_headers"])
        d["resp_headers"] = json.loads(d["resp_headers"])
        return d

    # ── attack-surface assets (the graph) ────────────────────────────────────
    def add_asset(self, target: str, kind: str, value: str,
                  parent_id: int | None = None, data: dict | None = None) -> int:
        """Insert an asset, or return the id of the existing (kind, value).

        Dedupes so the same host found twice is one node. A later call with a
        parent or data fills those in if the first call left them empty.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT id FROM assets WHERE target=? AND kind=? AND value=?",
                (target, kind, value)).fetchone()
            if row:
                aid = row["id"]
                if parent_id is not None:
                    self._db.execute("UPDATE assets SET parent_id=? WHERE id=? AND parent_id IS NULL",
                                     (parent_id, aid))
                if data:
                    self._db.execute("UPDATE assets SET data=? WHERE id=?",
                                     (json.dumps(data), aid))
                self._db.commit()
                return aid
            cur = self._db.execute(
                "INSERT INTO assets(target, kind, value, parent_id, data, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (target, kind, value, parent_id, json.dumps(data or {}), time.time()))
            self._db.commit()
            return cur.lastrowid

    def assets_for_target(self, target: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM assets WHERE target=? ORDER BY id", (target,)).fetchall()
        return [self._asset_row(r) for r in rows]

    @staticmethod
    def _asset_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["data"] = json.loads(d["data"])
        return d

    # ── coverage by vuln class ───────────────────────────────────────────────
    def record_coverage(self, target: str, vuln_class: str, status: str,
                        note: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO coverage(target, vuln_class, status, note, updated_at)"
                " VALUES (?,?,?,?,?)", (target, vuln_class, status, note, time.time()))
            self._db.commit()

    def class_coverage_map(self, target: str) -> dict[str, str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT vuln_class, status FROM coverage WHERE target=?", (target,)).fetchall()
        return {r["vuln_class"]: r["status"] for r in rows}
