"""
Security event logger — SQLite backed.
Stores: timestamp, session_id, prompt_hash (NOT plaintext), label, confidence, action, explanation.
"""
import hashlib
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from shared.config import LOG_DB_PATH


def _get_conn() -> sqlite3.Connection:
    Path(LOG_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(LOG_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            session_id  TEXT NOT NULL,
            prompt_hash TEXT NOT NULL,
            label       TEXT NOT NULL,
            confidence  REAL NOT NULL,
            action      TEXT NOT NULL,
            explanation TEXT,
            patterns    TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_event(
    session_id: str,
    prompt: str,
    label: str,
    confidence: float,
    action: str,           # "BLOCKED" | "FLAGGED" | "ALLOWED"
    explanation: str = "",
    patterns: list = None,
):
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
    conn = _get_conn()
    conn.execute(
        """INSERT INTO security_events
           (timestamp, session_id, prompt_hash, label, confidence, action, explanation, patterns)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(),
            session_id,
            prompt_hash,
            label,
            confidence,
            action,
            explanation,
            json.dumps(patterns or []),
        ),
    )
    conn.commit()
    conn.close()


def get_recent_events(limit: int = 50) -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM security_events WHERE action='BLOCKED'").fetchone()[0]
    by_label = conn.execute(
        "SELECT label, COUNT(*) as count FROM security_events GROUP BY label"
    ).fetchall()
    conn.close()
    return {
        "total_requests": total,
        "total_blocked": blocked,
        "by_label": {r["label"]: r["count"] for r in by_label},
    }
