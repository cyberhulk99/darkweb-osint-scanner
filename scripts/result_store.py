import sqlite3
import hashlib
import os
from datetime import datetime

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE, "data", "findings.db")


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            hash       TEXT    UNIQUE NOT NULL,
            tool       TEXT    NOT NULL,
            keyword    TEXT,
            content    TEXT,
            first_seen TEXT    NOT NULL,
            last_seen  TEXT    NOT NULL,
            hit_count  INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    return conn


def _hash(tool, content):
    return hashlib.sha256(f"{tool}|{content[:1000]}".encode()).hexdigest()


def is_new(tool, content):
    """Return True if this tool+content combination has never been seen before."""
    h = _hash(tool, content)
    conn = _conn()
    row = conn.execute("SELECT id FROM findings WHERE hash = ?", (h,)).fetchone()
    conn.close()
    return row is None


def record(tool, content, keyword=None):
    """Persist a finding. Returns True if it was new, False if a duplicate."""
    h = _hash(tool, content)
    now = datetime.now().isoformat()
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO findings (hash, tool, keyword, content, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
            (h, tool, keyword, content, now, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        conn.execute(
            "UPDATE findings SET last_seen=?, hit_count=hit_count+1 WHERE hash=?",
            (now, h),
        )
        conn.commit()
        return False
    finally:
        conn.close()


def get_recent(limit=20):
    """Return the most recent stored findings."""
    conn = _conn()
    rows = conn.execute(
        "SELECT tool, keyword, content, first_seen FROM findings ORDER BY first_seen DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows
