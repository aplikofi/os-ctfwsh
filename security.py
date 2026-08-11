"""
security.py
============
Small, dependency-free security helpers:

- CSRF token generation/verification (session-bound)
- In-memory submission rate limiting (per team / per IP)
- login_required / admin_required decorators
- basic input validation (email format, team name, password strength)
"""

import re
import secrets
import time
import threading
from functools import wraps

from flask import session, request, redirect, url_for, jsonify, abort, current_app

# ---------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------

def get_csrf_token():
    """Return the current session's CSRF token, creating one if needed."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(24)
        session["csrf_token"] = token
    return token


def verify_csrf(supplied_token):
    expected = session.get("csrf_token")
    return bool(expected) and bool(supplied_token) and secrets.compare_digest(
        expected, supplied_token
    )


def csrf_protect(view_func):
    """Decorator for state-changing routes (POST forms and JSON APIs)."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get(
                "X-CSRFToken"
            )
            if not verify_csrf(token):
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "Invalid or missing CSRF token."}), 400
                abort(400, description="Invalid or missing CSRF token.")
        return view_func(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("team_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def is_valid_email(email):
    return bool(email) and bool(EMAIL_RE.match(email.strip())) and len(email) <= 254


def is_valid_team_name(name):
    name = (name or "").strip()
    return 2 <= len(name) <= 40


def is_valid_password(pw):
    # Kept simple and beginner-friendly for a college event, while still
    # requiring a reasonable minimum length.
    return bool(pw) and len(pw) >= 8


# ---------------------------------------------------------------------
# Lightweight in-memory rate limiter
# ---------------------------------------------------------------------
# Suitable for a single-process local LAN event. Not distributed-safe,
# which is fine since this app is designed to run as one Flask process
# on the organizer's laptop.

class RateLimiter:
    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def check(self, key, max_count, window_seconds):
        """
        Returns True if the action is allowed (and records the hit),
        False if the caller has exceeded max_count within window_seconds.
        """
        now = time.time()
        with self._lock:
            timestamps = self._hits.get(key, [])
            timestamps = [t for t in timestamps if now - t < window_seconds]
            if len(timestamps) >= max_count:
                self._hits[key] = timestamps
                return False
            timestamps.append(now)
            self._hits[key] = timestamps
            return True


submit_limiter = RateLimiter()
auth_limiter = RateLimiter()


def rate_limited_response():
    return jsonify({"error": "Too many attempts. Please slow down and try again shortly."}), 429


def client_ip():
    # Local LAN event — X-Forwarded-For isn't trusted since there's no
    # reverse proxy in front of the app by default.
    return request.remote_addr or "unknown"
