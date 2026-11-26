"""Community reports: users can flag a link as a scam or as safe.

Stored in SQLite. On hosts with an ephemeral disk (such as Render's free tier)
the file can be reset on redeploy; set COMPPHISH_DB to a persistent path to keep it.
Only host + path are stored (query strings can hold tokens), and comments are
length-limited. Reports are community opinion, not verified evidence.
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

DB_PATH = os.getenv("COMPPHISH_DB", "/tmp/compphish_reports.db")
CATEGORIES = {"scam", "safe", "other"}
MAX_COMMENT = 300
RATE_LIMIT = 5          # reports
RATE_WINDOW = 3600      # per hour, per client
_hits: dict[str, deque] = defaultdict(deque)


def _key(url: str) -> str:
    p = urlparse(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("A valid http(s) URL is required.")
    return f"{p.hostname.lower()}{p.path.rstrip('/')}"[:300]


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.execute(
        "CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, key TEXT, "
        "category TEXT, comment TEXT, created REAL)"
    )
    c.execute("CREATE INDEX IF NOT EXISTS ix_key ON reports(key)")
    return c


def add_report(url: str, category: str, comment: str, client: str) -> dict:
    if category not in CATEGORIES:
        raise ValueError("Category must be scam, safe or other.")
    now = time.time()
    q = _hits[client]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise PermissionError("Too many reports. Please try again later.")
    key = _key(url)
    comment = " ".join((comment or "").split())[:MAX_COMMENT]
    with _conn() as c:
        c.execute("INSERT INTO reports(key,category,comment,created) VALUES(?,?,?,?)",
                  (key, category, comment, now))
    q.append(now)
    return summary(url)


def summary(url: str) -> dict:
    try:
        key = _key(url)
        with _conn() as c:
            rows = c.execute(
                "SELECT category, comment, created FROM reports WHERE key=? ORDER BY id DESC LIMIT 20",
                (key,),
            ).fetchall()
    except Exception:
        return {"status": "unavailable", "total": 0, "scam": 0, "safe": 0, "other": 0, "recent": []}
    counts = {c: 0 for c in CATEGORIES}
    for cat, _, _ in rows:
        counts[cat] += 1
    return {
        "status": "ok",
        "total": len(rows),
        **counts,
        "recent": [
            {"category": cat, "comment": com, "created": int(ts)} for cat, com, ts in rows[:5]
        ],
    }
