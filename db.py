"""
db.py
=====
SQLite helper layer for CyberQuest CTF.

All queries use parameterized SQL (never string concatenation) to avoid
SQL injection. Connections are opened per-request via Flask's `g` object
and closed automatically at teardown.
"""

import sqlite3
from datetime import datetime, timezone

from flask import g, current_app
from werkzeug.security import generate_password_hash

from config import CHALLENGES


def get_db():
    """Return a request-scoped SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_name TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    points INTEGER NOT NULL,
    flag_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS solved_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    challenge_id INTEGER NOT NULL,
    solved_at TEXT NOT NULL,
    UNIQUE(team_id, challenge_id),
    FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY(challenge_id) REFERENCES challenges(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    challenge_id INTEGER NOT NULL,
    is_correct INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY(challenge_id) REFERENCES challenges(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS event_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    event_start TEXT,
    duration_minutes INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);
"""


def init_db(app):
    """Create tables (if needed) and seed challenges / event settings."""
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()

        # Seed challenges (idempotent - only inserts codes that don't exist yet)
        existing_codes = {
            row["code"] for row in db.execute("SELECT code FROM challenges")
        }
        for chal in CHALLENGES:
            if chal["code"] in existing_codes:
                continue
            flag_hash = generate_password_hash(chal["flag"])
            db.execute(
                """INSERT INTO challenges (code, title, category, difficulty, points, flag_hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    chal["code"],
                    chal["title"],
                    chal["category"],
                    chal["difficulty"],
                    chal["points"],
                    flag_hash,
                ),
            )
        db.commit()

        # Seed event_settings row (single row, id=1) if missing
        row = db.execute("SELECT id FROM event_settings WHERE id = 1").fetchone()
        if row is None:
            db.execute(
                """INSERT INTO event_settings (id, event_start, duration_minutes, is_active)
                   VALUES (1, ?, ?, 1)""",
                (now_iso(), app.config["EVENT_DURATION_MINUTES"]),
            )
            db.commit()

        db.close()
