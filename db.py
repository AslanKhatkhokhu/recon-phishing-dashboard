"""
SQLite persistence layer for OSINT Dashboard.
Stores scans, vishing campaigns, and API keys.
"""

import json
import os
import sqlite3
import time
import threading

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osint_dashboard.db")
_local = threading.local()


def _conn() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(_DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init():
    """Create tables if they don't exist."""
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'running',
            inputs TEXT DEFAULT '{}',
            results TEXT DEFAULT '{}',
            logs TEXT DEFAULT '[]',
            started_at REAL,
            ended_at REAL
        );

        CREATE TABLE IF NOT EXISTS vishing_campaigns (
            id TEXT PRIMARY KEY,
            name TEXT,
            script_key TEXT,
            caller_id TEXT DEFAULT '',
            targets TEXT DEFAULT '[]',
            calls TEXT DEFAULT '[]',
            opener_audio_url TEXT DEFAULT '',
            created TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
            value TEXT DEFAULT '',
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS sip_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            server TEXT DEFAULT '',
            port INTEGER DEFAULT 5060,
            username TEXT DEFAULT '',
            password TEXT DEFAULT '',
            transport TEXT DEFAULT 'UDP',
            caller_id TEXT DEFAULT '',
            active INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS ivr_flows (
            flow_id TEXT PRIMARY KEY,
            nodes TEXT DEFAULT '{}',
            created_at TEXT
        );
    """)
    conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Scans
# ──────────────────────────────────────────────────────────────────────────────

def save_scan(scan: dict):
    """Insert or update a scan record."""
    conn = _conn()
    conn.execute(
        """INSERT OR REPLACE INTO scans (id, status, inputs, results, logs, started_at, ended_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            scan["id"],
            scan.get("status", "running"),
            json.dumps(scan.get("inputs", {})),
            json.dumps(scan.get("results", {})),
            json.dumps(scan.get("logs", [])),
            scan.get("started_at"),
            scan.get("ended_at"),
        ),
    )
    conn.commit()


def get_scan(scan_id: str) -> dict | None:
    row = _conn().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    return _row_to_scan(row)


def list_scans(limit: int = 50) -> list:
    rows = _conn().execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_scan(r) for r in rows]


def delete_scan(scan_id: str):
    _conn().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    _conn().commit()


def _row_to_scan(row) -> dict:
    return {
        "id": row["id"],
        "status": row["status"],
        "inputs": json.loads(row["inputs"] or "{}"),
        "results": json.loads(row["results"] or "{}"),
        "logs": json.loads(row["logs"] or "[]"),
        "started_at": row["started_at"],
        "ended_at": row["ended_at"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Vishing campaigns
# ──────────────────────────────────────────────────────────────────────────────

def save_campaign(camp: dict):
    conn = _conn()
    conn.execute(
        """INSERT OR REPLACE INTO vishing_campaigns
           (id, name, script_key, caller_id, targets, calls, opener_audio_url, created)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            camp["id"],
            camp.get("name", ""),
            camp.get("script_key", ""),
            camp.get("caller_id", ""),
            json.dumps(camp.get("targets", [])),
            json.dumps(camp.get("calls", [])),
            camp.get("opener_audio_url", ""),
            camp.get("created", ""),
        ),
    )
    conn.commit()


def get_campaign(camp_id: str) -> dict | None:
    row = _conn().execute("SELECT * FROM vishing_campaigns WHERE id = ?", (camp_id,)).fetchone()
    if not row:
        return None
    return _row_to_campaign(row)


def list_campaigns() -> list:
    rows = _conn().execute("SELECT * FROM vishing_campaigns ORDER BY created DESC").fetchall()
    return [_row_to_campaign(r) for r in rows]


def delete_campaign(camp_id: str):
    _conn().execute("DELETE FROM vishing_campaigns WHERE id = ?", (camp_id,))
    _conn().commit()


def _row_to_campaign(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "script_key": row["script_key"],
        "caller_id": row["caller_id"],
        "targets": json.loads(row["targets"] or "[]"),
        "calls": json.loads(row["calls"] or "[]"),
        "opener_audio_url": row["opener_audio_url"],
        "created": row["created"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# API keys (simple obfuscation — not encryption for usability)
# ──────────────────────────────────────────────────────────────────────────────

def save_api_key(key_id: str, value: str):
    conn = _conn()
    conn.execute(
        "INSERT OR REPLACE INTO api_keys (key_id, value, updated_at) VALUES (?, ?, ?)",
        (key_id, value, time.strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()


def get_api_key(key_id: str) -> str:
    row = _conn().execute("SELECT value FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
    return row["value"] if row else ""


def list_api_keys() -> dict:
    """Return {key_id: bool(configured)} for all stored keys."""
    rows = _conn().execute("SELECT key_id, value FROM api_keys").fetchall()
    return {r["key_id"]: bool(r["value"]) for r in rows}


def load_api_keys_to_env():
    """Load all stored API keys into os.environ on startup."""
    rows = _conn().execute("SELECT key_id, value FROM api_keys WHERE value != ''").fetchall()
    for r in rows:
        os.environ.setdefault(r["key_id"], r["value"])
    return len(rows)


