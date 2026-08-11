"""
app.py
======
CyberQuest CTF — local multiplayer edition.

Run with:
    python app.py

Serves on 0.0.0.0:5000 by default so teammates on the same LAN/Wi-Fi can
connect via http://<host-ip>:5000
"""

import os
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, send_from_directory, abort, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config, CHALLENGES, MAX_POSSIBLE_SCORE
from db import get_db, close_db, init_db, now_iso
from security import (
    get_csrf_token, csrf_protect, login_required, admin_required,
    is_valid_email, is_valid_team_name, is_valid_password,
    submit_limiter, auth_limiter, rate_limited_response, client_ip,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CHALLENGE_ASSETS_DIR = os.path.join(BASE_DIR, "challenge_assets")

app = Flask(__name__)
app.config.from_object(Config)
app.teardown_appcontext(close_db)


# =====================================================================
# Template globals
# =====================================================================

@app.context_processor
def inject_globals():
    current_team_score = None
    if session.get("team_id"):
        db = get_db()
        row = db.execute(
            "SELECT score FROM teams WHERE id = ?", (session["team_id"],)
        ).fetchone()
        if row:
            current_team_score = row["score"]
    return {
        "csrf_token": get_csrf_token,
        "current_team_name": session.get("team_name"),
        "current_team_score": current_team_score,
        "is_admin": bool(session.get("admin_id")),
    }


# =====================================================================
# Event timer helpers
# =====================================================================

def get_event_settings():
    db = get_db()
    row = db.execute("SELECT * FROM event_settings WHERE id = 1").fetchone()
    return row


def event_status():
    """Returns dict with is_active, remaining_seconds, ends_at (ISO)."""
    row = get_event_settings()
    if row is None:
        return {"is_active": False, "remaining_seconds": 0, "ended": True}

    start = datetime.fromisoformat(row["event_start"])
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    end = start + timedelta(minutes=row["duration_minutes"])
    now = datetime.now(timezone.utc)
    remaining = (end - now).total_seconds()

    admin_stopped = row["is_active"] == 0
    time_expired = remaining <= 0
    ended = admin_stopped or time_expired

    return {
        "is_active": not ended,
        "remaining_seconds": max(0, int(remaining)) if not admin_stopped else 0,
        "ended": ended,
        "ends_at": end.isoformat(),
    }


# =====================================================================
# Public pages
# =====================================================================

@app.route("/")
def index():
    team_score = None
    solved_count = None
    if session.get("team_id"):
        db = get_db()
        team = db.execute(
            "SELECT * FROM teams WHERE id = ?", (session["team_id"],)
        ).fetchone()
        if team:
            team_score = team["score"]
            solved_count = db.execute(
                "SELECT COUNT(*) c FROM solved_challenges WHERE team_id = ?",
                (session["team_id"],),
            ).fetchone()["c"]

    return render_template(
        "index.html",
        team_score=team_score,
        solved_count=solved_count,
        total_challenges=len(CHALLENGES),
        event=event_status(),
    )


@app.route("/rules")
def rules():
    return render_template("rules.html")


# =====================================================================
# Registration / Login / Logout
# =====================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("team_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if not auth_limiter.check(f"register:{client_ip()}", Config.AUTH_RATE_LIMIT_COUNT, Config.AUTH_RATE_LIMIT_WINDOW_SECONDS):
            flash("Too many attempts. Please wait a moment and try again.", "error")
            return render_template("register.html"), 429

        token = request.form.get("csrf_token")
        from security import verify_csrf
        if not verify_csrf(token):
            flash("Your form session expired. Please try again.", "error")
            return render_template("register.html"), 400

        team_name = (request.form.get("team_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""

        errors = []
        if not is_valid_team_name(team_name):
            errors.append("Team name must be between 2 and 40 characters.")
        if not is_valid_email(email):
            errors.append("Please enter a valid email address.")
        if not is_valid_password(password):
            errors.append("Password must be at least 8 characters long.")
        if password != confirm:
            errors.append("Passwords do not match.")

        db = get_db()
        if not errors:
            existing_name = db.execute(
                "SELECT id FROM teams WHERE team_name = ?", (team_name,)
            ).fetchone()
            existing_email = db.execute(
                "SELECT id FROM teams WHERE email = ?", (email,)
            ).fetchone()
            if existing_name:
                errors.append("That team name is already taken.")
            if existing_email:
                errors.append("That email is already registered.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", team_name=team_name, email=email)

        password_hash = generate_password_hash(password)
        cur = db.execute(
            """INSERT INTO teams (team_name, email, password_hash, created_at, score)
               VALUES (?, ?, ?, ?, 0)""",
            (team_name, email, password_hash, now_iso()),
        )
        db.commit()
        team_id = cur.lastrowid

        session.clear()
        session.permanent = True
        session["team_id"] = team_id
        session["team_name"] = team_name

        flash("Team registered successfully. Good luck!", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("team_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if not auth_limiter.check(f"login:{client_ip()}", Config.AUTH_RATE_LIMIT_COUNT, Config.AUTH_RATE_LIMIT_WINDOW_SECONDS):
            flash("Too many attempts. Please wait a moment and try again.", "error")
            return render_template("login.html"), 429

        token = request.form.get("csrf_token")
        from security import verify_csrf
        if not verify_csrf(token):
            flash("Your form session expired. Please try again.", "error")
            return render_template("login.html"), 400

        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        next_url = request.values.get("next")

        db = get_db()
        team = db.execute("SELECT * FROM teams WHERE email = ?", (email,)).fetchone()

        if team is None or not check_password_hash(team["password_hash"], password):
            flash("Invalid email or password.", "error")
            return render_template("login.html", email=email, next=next_url), 401

        session.clear()
        session.permanent = True
        session["team_id"] = team["id"]
        session["team_name"] = team["team_name"]

        return redirect(next_url or url_for("dashboard"))

    return render_template("login.html", next=request.values.get("next"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# =====================================================================
# Player dashboard / challenges
# =====================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    team = db.execute("SELECT * FROM teams WHERE id = ?", (session["team_id"],)).fetchone()
    if team is None:
        session.clear()
        return redirect(url_for("login"))

    solved_count = db.execute(
        "SELECT COUNT(*) c FROM solved_challenges WHERE team_id = ?",
        (team["id"],),
    ).fetchone()["c"]

    return render_template(
        "dashboard.html",
        team=team,
        solved_count=solved_count,
        total_challenges=len(CHALLENGES),
        event=event_status(),
    )


@app.route("/challenges")
@login_required
def challenges_list():
    db = get_db()
    solved_rows = db.execute(
        "SELECT challenge_id FROM solved_challenges WHERE team_id = ?",
        (session["team_id"],),
    ).fetchall()
    solved_ids = {row["challenge_id"] for row in solved_rows}

    db_challenges = db.execute("SELECT * FROM challenges ORDER BY id").fetchall()

    # Merge DB rows (id, points, etc.) with static display config (story, hint)
    meta_by_code = {c["code"]: c for c in CHALLENGES}
    merged = []
    for row in db_challenges:
        meta = meta_by_code.get(row["code"], {})
        merged.append({
            "id": row["id"],
            "code": row["code"],
            "title": row["title"],
            "category": row["category"],
            "category_key": meta.get("category_key", "web"),
            "difficulty": row["difficulty"],
            "points": row["points"],
            "solved": row["id"] in solved_ids,
        })

    return render_template("challenges.html", challenges=merged, event=event_status())


@app.route("/challenge/<code>")
@login_required
def challenge_detail(code):
    db = get_db()
    row = db.execute("SELECT * FROM challenges WHERE code = ?", (code,)).fetchone()
    if row is None:
        abort(404)

    meta = next((c for c in CHALLENGES if c["code"] == code), None)
    if meta is None:
        abort(404)

    solved = db.execute(
        "SELECT 1 FROM solved_challenges WHERE team_id = ? AND challenge_id = ?",
        (session["team_id"], row["id"]),
    ).fetchone() is not None

    resp = app.make_response(
        render_template(
            "challenge.html",
            challenge=row,
            meta=meta,
            solved=solved,
            event=event_status(),
        )
    )

    # Cookie Hunt: the server (not client JS) bakes the flag into a cookie
    # when this specific challenge page is loaded. This is the intended
    # mechanic of the challenge — the player is meant to find it via
    # DevTools → Application/Storage → Cookies.
    if code == "cookie-hunt":
        resp.set_cookie("ctf_flag", meta["flag"], max_age=3600, httponly=False, samesite="Lax")

    return resp


# =====================================================================
# Flag submission API (server-side validation only)
# =====================================================================

@app.route("/api/submit/<code>", methods=["POST"])
@login_required
@csrf_protect
def submit_flag(code):
    status = event_status()
    if status["ended"]:
        return jsonify({"result": "event-ended", "message": "CTF ENDED — submissions are closed."}), 403

    if not submit_limiter.check(
        f"submit:{session['team_id']}",
        Config.SUBMIT_RATE_LIMIT_COUNT,
        Config.SUBMIT_RATE_LIMIT_WINDOW_SECONDS,
    ):
        return rate_limited_response()

    data = request.get_json(silent=True) or {}
    submitted = (data.get("flag") or "").strip()

    if not submitted:
        return jsonify({"result": "incorrect", "message": "Please enter a flag."}), 400

    db = get_db()
    chal = db.execute("SELECT * FROM challenges WHERE code = ?", (code,)).fetchone()
    if chal is None:
        abort(404)

    team_id = session["team_id"]

    already = db.execute(
        "SELECT 1 FROM solved_challenges WHERE team_id = ? AND challenge_id = ?",
        (team_id, chal["id"]),
    ).fetchone()
    if already:
        return jsonify({
            "result": "already-solved",
            "message": "You already solved this one — nice work!",
        })

    is_correct = check_password_hash(chal["flag_hash"], submitted)

    db.execute(
        """INSERT INTO submissions (team_id, challenge_id, is_correct, submitted_at)
           VALUES (?, ?, ?, ?)""",
        (team_id, chal["id"], 1 if is_correct else 0, now_iso()),
    )

    if is_correct:
        try:
            db.execute(
                """INSERT INTO solved_challenges (team_id, challenge_id, solved_at)
                   VALUES (?, ?, ?)""",
                (team_id, chal["id"], now_iso()),
            )
            db.execute(
                "UPDATE teams SET score = score + ? WHERE id = ?",
                (chal["points"], team_id),
            )
            db.commit()
        except Exception:
            db.rollback()
            # Someone else / duplicate request already solved it in a race —
            # treat as already-solved rather than double-award.
            return jsonify({
                "result": "already-solved",
                "message": "You already solved this one — nice work!",
            })

        return jsonify({
            "result": "correct",
            "message": "Correct! \U0001F389 Points added to your score.",
            "points": chal["points"],
        })
    else:
        db.commit()
        return jsonify({
            "result": "incorrect",
            "message": "Incorrect flag. Try again!",
        })


# =====================================================================
# Scoreboard
# =====================================================================

@app.route("/scoreboard")
def scoreboard():
    return render_template("scoreboard.html", event=event_status())


@app.route("/api/scoreboard")
def api_scoreboard():
    db = get_db()
    teams = db.execute(
        "SELECT id, team_name, score FROM teams ORDER BY score DESC, created_at ASC"
    ).fetchall()

    solved_counts = {
        row["team_id"]: row["c"]
        for row in db.execute(
            "SELECT team_id, COUNT(*) c FROM solved_challenges GROUP BY team_id"
        ).fetchall()
    }

    board = []
    for i, t in enumerate(teams):
        board.append({
            "rank": i + 1,
            "team_name": t["team_name"],
            "score": t["score"],
            "solved": solved_counts.get(t["id"], 0),
            "total": len(CHALLENGES),
            "is_you": t["id"] == session.get("team_id"),
        })

    return jsonify({"scoreboard": board, "event": event_status()})


# =====================================================================
# Event timer API
# =====================================================================

@app.route("/api/time-remaining")
def api_time_remaining():
    return jsonify(event_status())


# =====================================================================
# Protected challenge asset routes
# (kept outside /static/ so they require authentication and aren't
#  directly guessable/scrapeable by anyone who isn't logged in)
# =====================================================================

@app.route("/secret/flag.txt")
@login_required
def hidden_file_asset():
    return send_from_directory(os.path.join(CHALLENGE_ASSETS_DIR, "secret"), "flag.txt")


@app.route("/challenge-assets/mystery.jpg")
@login_required
def mystery_image_asset():
    return send_from_directory(CHALLENGE_ASSETS_DIR, "mystery.jpg")


@app.route("/challenge-assets/mystery_metadata.txt")
@login_required
def mystery_metadata_asset():
    return send_from_directory(CHALLENGE_ASSETS_DIR, "mystery_metadata.txt")


# =====================================================================
# Admin panel
# =====================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        if not auth_limiter.check(f"admin-login:{client_ip()}", Config.AUTH_RATE_LIMIT_COUNT, Config.AUTH_RATE_LIMIT_WINDOW_SECONDS):
            flash("Too many attempts. Please wait a moment and try again.", "error")
            return render_template("admin_login.html"), 429

        token = request.form.get("csrf_token")
        from security import verify_csrf
        if not verify_csrf(token):
            flash("Your form session expired. Please try again.", "error")
            return render_template("admin_login.html"), 400

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        db = get_db()
        admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()

        if admin is None or not check_password_hash(admin["password_hash"], password):
            flash("Invalid admin credentials.", "error")
            return render_template("admin_login.html"), 401

        session.clear()
        session.permanent = True
        session["admin_id"] = admin["id"]
        session["admin_username"] = admin["username"]
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    teams = db.execute(
        "SELECT * FROM teams ORDER BY score DESC, created_at ASC"
    ).fetchall()

    solved_counts = {
        row["team_id"]: row["c"]
        for row in db.execute(
            "SELECT team_id, COUNT(*) c FROM solved_challenges GROUP BY team_id"
        ).fetchall()
    }

    total_teams = len(teams)
    total_submissions = db.execute("SELECT COUNT(*) c FROM submissions").fetchone()["c"]
    total_correct = db.execute(
        "SELECT COUNT(*) c FROM submissions WHERE is_correct = 1"
    ).fetchone()["c"]

    recent_submissions = db.execute(
        """SELECT s.submitted_at, s.is_correct, t.team_name, c.title
           FROM submissions s
           JOIN teams t ON t.id = s.team_id
           JOIN challenges c ON c.id = s.challenge_id
           ORDER BY s.submitted_at DESC
           LIMIT 25"""
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        teams=teams,
        solved_counts=solved_counts,
        total_teams=total_teams,
        total_submissions=total_submissions,
        total_correct=total_correct,
        recent_submissions=recent_submissions,
        event=event_status(),
        event_settings=get_event_settings(),
        total_challenges=len(CHALLENGES),
        max_score=MAX_POSSIBLE_SCORE,
    )


@app.route("/admin/reset-team/<int:team_id>", methods=["POST"])
@admin_required
@csrf_protect
def admin_reset_team(team_id):
    db = get_db()
    db.execute("DELETE FROM solved_challenges WHERE team_id = ?", (team_id,))
    db.execute("DELETE FROM submissions WHERE team_id = ?", (team_id,))
    db.execute("UPDATE teams SET score = 0 WHERE id = ?", (team_id,))
    db.commit()
    flash("Team progress reset.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reset-event", methods=["POST"])
@admin_required
@csrf_protect
def admin_reset_event():
    db = get_db()
    db.execute("DELETE FROM solved_challenges")
    db.execute("DELETE FROM submissions")
    db.execute("UPDATE teams SET score = 0")

    duration = request.form.get("duration_minutes", type=int) or Config.EVENT_DURATION_MINUTES
    db.execute(
        "UPDATE event_settings SET event_start = ?, duration_minutes = ?, is_active = 1 WHERE id = 1",
        (now_iso(), duration),
    )
    db.commit()
    flash("Event has been fully reset and the timer restarted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/end-event", methods=["POST"])
@admin_required
@csrf_protect
def admin_end_event():
    db = get_db()
    db.execute("UPDATE event_settings SET is_active = 0 WHERE id = 1")
    db.commit()
    flash("Event ended. Submissions are now closed.", "success")
    return redirect(url_for("admin_dashboard"))


# =====================================================================
# Misc
# =====================================================================

@app.route("/robots.txt")
def robots_txt():
    return send_from_directory(app.static_folder, "robots.txt")


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    init_db(app)
    print(f"\n CyberQuest CTF starting on http://{Config.HOST}:{Config.PORT}")
    print(" Share this with participants on the same Wi-Fi/LAN:")
    print(f"   http://<this-computer-ip>:{Config.PORT}\n")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
