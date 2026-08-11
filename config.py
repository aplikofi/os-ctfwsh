"""
config.py
=========
Central configuration for the CyberQuest CTF Flask application.

Reads sensitive/deployment settings from environment variables where
practical, with sane defaults for a local college-LAN event.
"""

import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _load_or_create_secret_key():
    """
    Persist a random Flask secret key to a local file so sessions survive
    server restarts, unless SECRET_KEY is provided via environment variable.
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    key_path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            existing = f.read().strip()
            if existing:
                return existing

    new_key = secrets.token_hex(32)
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(new_key)
    return new_key


class Config:
    # ---- Core Flask ----
    SECRET_KEY = _load_or_create_secret_key()

    # ---- Database ----
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH", os.path.join(BASE_DIR, "database.db")
    )

    # ---- Session / cookie security ----
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Set SESSION_COOKIE_SECURE=True only if you serve over HTTPS.
    # A local LAN CTF event typically runs over plain HTTP, so this
    # defaults to False. Override via the FORCE_SECURE_COOKIES env var.
    SESSION_COOKIE_SECURE = os.environ.get("FORCE_SECURE_COOKIES", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8  # 8 hours

    # ---- Event settings ----
    EVENT_DURATION_MINUTES = int(os.environ.get("EVENT_DURATION_MINUTES", "360"))

    # ---- Network ----
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

    # ---- Rate limiting (submission throttling) ----
    SUBMIT_RATE_LIMIT_COUNT = 8          # max attempts
    SUBMIT_RATE_LIMIT_WINDOW_SECONDS = 30  # per this many seconds

    # ---- Auth throttling (login/register) ----
    AUTH_RATE_LIMIT_COUNT = 10
    AUTH_RATE_LIMIT_WINDOW_SECONDS = 60


# =========================================================
# Challenge definitions
# =========================================================
# This is the ONLY place correct flags live. Nothing here is ever sent
# to the browser directly — flags are hashed into the database at
# startup and compared server-side using Werkzeug's secure hash check.
#
# code        -> used in URLs (/challenge/<code>) and DB lookups
# flag        -> the correct answer (server-side only)
# =========================================================

CHALLENGES = [
    {
        "code": "find-source",
        "title": "Find Me",
        "category": "Web",
        "category_key": "web",
        "difficulty": "Easy",
        "points": 100,
        "flag": "CTF{view_source_master}",
        "hint": (
            "Sometimes the browser shows more than what you see. Try "
            "right-click \u2192 \"View Page Source\" (or press Ctrl+U on Windows)."
        ),
        "story": (
            "Welcome to your first challenge! Every webpage sends more to "
            "your browser than what's rendered on screen. Sometimes "
            "developers leave notes, comments, or forgotten data behind in "
            "the raw HTML."
        ),
    },
    {
        "code": "base64",
        "title": "Secret Decoder",
        "category": "Cryptography",
        "category_key": "crypto",
        "difficulty": "Easy",
        "points": 100,
        "flag": "CTF{base64_master}",
        "encoded_data": "Q1RGe2Jhc2U2NF9tYXN0ZXJ9",
        "hint": (
            "Try identifying the encoding. It uses letters, numbers, and "
            "often ends with \"=\" padding \u2014 a quick web search for "
            "\"online decoder\" for this encoding type will help."
        ),
        "story": (
            "Our intelligence team intercepted the following transmission. "
            "It looks scrambled, but it's actually encoded using a very "
            "common text-encoding scheme. Decode it to reveal the flag."
        ),
    },
    {
        "code": "cookie-hunt",
        "title": "Cookie Hunt",
        "category": "Web",
        "category_key": "web",
        "difficulty": "Easy",
        "points": 150,
        "flag": "CTF{cookie_hunter}",
        "hint": (
            "Open your browser's Developer Tools (F12 on Windows), then go "
            "to the Application tab (Chrome/Edge) or Storage tab (Firefox) "
            "\u2192 Cookies \u2192 this page's address. Look for a cookie "
            "named ctf_flag."
        ),
        "story": (
            "This page quietly baked something into your browser the "
            "moment it loaded. Cookies sometimes remember more than your "
            "username."
        ),
    },
    {
        "code": "hidden-file",
        "title": "Hidden File",
        "category": "Web",
        "category_key": "web",
        "difficulty": "Easy",
        "points": 150,
        "flag": "CTF{hidden_directory}",
        "hint": (
            "Search engines and security tools often check a file called "
            "robots.txt at the root of a site to see what the owner "
            "doesn't want indexed. This site has one too \u2014 try opening "
            "it in your browser. It will point you toward a hidden path. "
            "You must be logged in to access it."
        ),
        "story": (
            "Not every page is linked from the homepage. Real websites "
            "often have files and folders that exist on the server but "
            "aren't shown in any menu \u2014 and site owners sometimes leave "
            "clues about them in unlikely places."
        ),
    },
    {
        "code": "image-mystery",
        "title": "Image Mystery",
        "category": "Forensics",
        "category_key": "forensics",
        "difficulty": "Easy",
        "points": 200,
        "flag": "CTF{metadata_detective}",
        "hint": (
            "Download the image, then check its properties. On Windows: "
            "right-click the file \u2192 Properties \u2192 Details tab, and "
            "look at the \"Comments\" / \"Title\" fields. A plain-text "
            "export of the metadata is also provided below if needed."
        ),
        "story": (
            "Images can contain information you cannot see just by "
            "looking at them. Every photo carries hidden metadata \u2014 "
            "camera details, notes, sometimes even secrets left behind by "
            "whoever created the file."
        ),
    },
]

MAX_POSSIBLE_SCORE = sum(c["points"] for c in CHALLENGES)
