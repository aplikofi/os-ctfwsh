# CyberQuest CTF — Local Multiplayer Edition

A local-network multiplayer Capture The Flag platform for a college
tech event, built with **Flask + SQLite**. It preserves the original
CyberQuest CTF look, feel, and all 5 challenges, but moves scoring,
authentication, and flag validation entirely to the server.

Max possible score: **700 points** across 5 challenges.

---

## 1. Folder Structure

```
CyberQuest-CTF/
│
├── app.py                     # Flask app + all routes
├── config.py                  # Settings + challenge definitions (flags live only here)
├── db.py                      # SQLite schema, connection helper, seeding
├── security.py                # CSRF, rate limiting, auth decorators, validation
├── create_admin.py            # CLI tool to create the first admin account
├── requirements.txt
├── README.md
├── database.db                 # Created automatically on first run (not shipped)
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── challenges.html
│   ├── challenge.html
│   ├── scoreboard.html
│   ├── rules.html
│   ├── admin_login.html
│   ├── admin_dashboard.html
│   └── 404.html
│
├── static/
│   ├── css/style.css           # Original CyberQuest CTF theme, unchanged
│   ├── js/script.js            # UI only — no flags, no scoring logic
│   └── robots.txt              # Hint for the Hidden File challenge
│
└── challenge_assets/            # Served only to logged-in teams
    ├── mystery.jpg               # Flag embedded in real EXIF metadata
    ├── mystery_metadata.txt      # Plain-text fallback of that metadata
    └── secret/flag.txt           # Hidden File challenge's target file
```

---

## 2. How flags are protected

- Correct flags exist in exactly one place server-side: `config.py` →
  `CHALLENGES`. That file never gets sent to the browser.
- On startup, each flag is hashed with Werkzeug's `generate_password_hash`
  and stored in the `challenges.flag_hash` column. The plaintext is
  discarded from the database entirely.
- When a player submits a flag, the browser POSTs the guess to
  `/api/submit/<code>`. The Flask server compares it against the hash
  using `check_password_hash` and responds only with `correct`,
  `incorrect`, or `already-solved` — never the actual answer.
- `static/js/script.js` contains **no flags and no comparison logic**.
- Two challenges intentionally place *discoverable* material in
  player-facing output, because that's the whole point of the
  challenge — but the actual pass/fail decision still happens on the
  server:
  - **Find Me** — the flag text appears in an HTML comment (view-source).
  - **Cookie Hunt** — the flag is set as a cookie value by the Flask
    response (`Set-Cookie`), not by client JavaScript.
  - **Hidden File** / **Image Mystery** assets are served from
    `challenge_assets/`, which sits outside `static/` and requires a
    logged-in session to fetch.

---

## 3. Windows Installation

1. Install **Python 3.10+** from python.org if you don't already have it
   (check "Add Python to PATH" during install).
2. Copy the `CyberQuest-CTF` folder onto the organizer's laptop.
3. Open **Command Prompt** in that folder (Shift+Right-click → "Open
   PowerShell/Command window here").
4. Install dependencies:
   ```
   python -m pip install -r requirements.txt
   ```

---

## 4. Create the First Admin Account

Run this once, before the event:

```
python create_admin.py
```

You'll be prompted for a username and password (input is hidden).
This also creates and seeds `database.db` if it doesn't exist yet.

Non-interactive alternative (useful for scripted setup):

```
set ADMIN_USERNAME=organizer
set ADMIN_PASSWORD=ChangeThisPassword123
python create_admin.py
```

The admin password is never hard-coded anywhere in the project — it's
only ever entered interactively or via environment variable.

---

## 5. Start the Server

### Option A — Quick start (Flask's built-in dev server)

```
python app.py
```

You should see:

```
CyberQuest CTF starting on http://0.0.0.0:5000
Share this with participants on the same Wi-Fi/LAN:
  http://<this-computer-ip>:5000
```

This is fine for testing and small events, but Flask's own server prints
a warning that it isn't meant for production use.

### Option B — Recommended for the actual event (Waitress)

[Waitress](https://docs.pylonsproject.org/projects/waitress/) is a
lightweight, production-grade WSGI server that works well on Windows
and is already included in `requirements.txt`. Run:

```
python -m waitress --host=0.0.0.0 --port=5000 app:app
```

- `app:app` refers to the `app` Flask object inside `app.py` — no
  changes needed, it works as-is.
- This still serves on `0.0.0.0:5000`, exactly like Option A, so
  everything below (LAN access, firewall, etc.) applies the same way.
- **Note:** Waitress serves requests but does not run the app's
  `if __name__ == "__main__":` startup block, so the database/admin
  account must already exist — run `python create_admin.py` first (see
  step 4), since that also initializes `database.db`.

Either option keeps this window open for the duration of the event —
closing it stops the server for everyone.

---

## 6. Connect Participants on the Same LAN

**On the organizer's laptop:**

1. Open Command Prompt and run:
   ```
   ipconfig
   ```
2. Find the **IPv4 Address** under your active Wi-Fi/Ethernet adapter,
   e.g. `192.168.1.10`.

**Allow the app through Windows Firewall (first time only):**

1. When you first start `app.py`, Windows may show a firewall prompt —
   click **Allow access** (for Private networks at minimum).
2. If you don't see the prompt, or need to add it manually: Windows
   Security → Firewall & network protection → Allow an app through
   firewall → Add `python.exe` → check Private → OK.
   Alternatively, open port 5000 directly: Advanced settings → Inbound
   Rules → New Rule → Port → TCP 5000 → Allow.

**On each participant's device (same Wi-Fi):**

1. Open a browser.
2. Go to `http://192.168.1.10:5000` (use the organizer's actual IP).
3. Register a team and start solving. No Python installation needed on
   participant devices — only the organizer's machine needs Python.

---

## 7. Testing Instructions

Quick smoke test as a participant:

1. Go to `/register`, create a team, confirm you land on `/dashboard`.
2. Open **Challenges**, click into **Find Me**, view page source
   (Ctrl+U), find the flag in the HTML comment, submit it — should show
   "Correct! 🎉" and update your score.
3. Repeat for **Secret Decoder** (Base64-decode the shown string),
   **Cookie Hunt** (DevTools → Application/Storage → Cookies →
   `ctf_flag`), **Hidden File** (check `/robots.txt` → follow the
   disallowed path → read the file), and **Image Mystery** (download
   `mystery.jpg` → check file Properties → Details, or use the provided
   metadata text export).
4. Confirm the **Scoreboard** updates within a few seconds without
   reloading the page.
5. Try submitting a solved challenge's flag again — should say
   "already solved" and not add extra points.
6. Log out, try opening `/challenges` directly — should redirect to
   `/login`.

Admin smoke test:

1. Go to `/admin/login`, sign in with the account from step 4.
2. Confirm you can see all teams, emails, scores, and solved counts.
3. Confirm the public `/scoreboard` does **not** show emails.
4. Try `Reset` on a test team — its score/solved should clear.

---

## 8. Stopping the Server

Both Option A and Option B run in the foreground of your Command
Prompt window. To stop the server:

- Click into that Command Prompt window.
- Press **Ctrl+C**.
- Wait for the prompt to return (it may take a second to shut down cleanly).

Closing the Command Prompt window entirely also stops the server, but
Ctrl+C is the cleaner way to do it.

---

## 9. Full Fresh Start Before Competition Day

The admin panel's **Reset Entire Event** (see below) clears scores and
progress but keeps existing team registrations. If you want a
completely empty slate — no leftover teams from testing — before the
real event starts:

1. Stop the server (Ctrl+C).
2. Delete `database.db` from the project folder.
3. Re-run:
   ```
   python create_admin.py
   ```
   This recreates the database from scratch (fresh tables, fresh
   challenge seeding) and sets up your admin account again.
4. Start the server again (Option A or B from step 5).

Your `.secret_key` file (used to sign login sessions) can be left as-is
— there's no need to delete it.

---

## 10. Resetting the Event (during/after testing, without wiping teams)

From `/admin/dashboard`:

- **End Event Now** — immediately closes flag submissions (scoreboard
  stays viewable). Useful if you need to stop early.
- **Reset Entire Event** — wipes every team's score and solved
  challenges, and restarts the countdown timer with the duration you
  specify (in minutes). Team accounts themselves are kept — only
  progress and the timer reset.

## 11. Resetting a Single Team

From `/admin/dashboard`, find the team's row and click **Reset**. This
clears that team's score and solved challenges only; other teams are
unaffected.

---

## 12. Backing Up the Database

The entire event lives in one file: `database.db`, in the project root.

To back it up, just copy the file while the server isn't actively
writing to it (e.g. during a lull, or briefly stop `app.py`):

```
copy database.db database_backup_2026-08-10.db
```

To restore, stop the server, replace `database.db` with your backup,
and restart `python app.py`.

---

## 13. Configuration

Environment variables (optional — sensible defaults are used otherwise):

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | Flask session signing key | Auto-generated and saved to `.secret_key` |
| `EVENT_DURATION_MINUTES` | Event length | `360` (6 hours) |
| `HOST` | Bind address | `0.0.0.0` |
| `PORT` | Port | `5000` |
| `DATABASE_PATH` | SQLite file location | `database.db` in project root |
| `FORCE_SECURE_COOKIES` | Set to `1` if serving over HTTPS | `0` |

Example (Windows Command Prompt):
```
set EVENT_DURATION_MINUTES=240
python app.py
```

---

## 14. Troubleshooting

**Other laptops can't reach `http://<ip>:5000`**
- Confirm all devices are on the *same* Wi-Fi network (not guest/isolated Wi-Fi — some campus networks block device-to-device traffic; a personal hotspot or a dedicated event router works best).
- Re-check the IP with `ipconfig` — it can change if you reconnect to Wi-Fi.
- Confirm Windows Firewall is allowing `python.exe` / port 5000 (see step 6).
- Try `http://127.0.0.1:5000` on the organizer's own laptop first, to confirm the server itself is running.

**"Address already in use" when starting `app.py`**
- Another instance of the server is already running. Close the other Command Prompt window, or change the port with `set PORT=5001`.

**Forgot the admin password**
- Run `python create_admin.py` again with the same username — it updates the password for an existing admin.

**A team forgot their password**
- There's no self-service password reset (by design, to keep the app simple for a short event). Recreate their team from `/admin/dashboard` isn't built in either — the simplest fix is to register a new team, or directly edit `database.db` for a hash reset. For a short college event, re-registering under a slightly different team name is usually easiest.

**Scoreboard looks frozen**
- It polls automatically every 5 seconds — check your network connection. A manual refresh always shows the current server state too.

**"Invalid or missing CSRF token" error**
- This appears if a form page was left open a very long time before submitting, or cookies were cleared mid-session. Refresh the page and try again.

**`python -m waitress ...` fails with "No module named waitress"**
- Re-run `python -m pip install -r requirements.txt` — Waitress is listed there. Confirm you're using the same Python install both times (`python -m pip --version` should show a matching path).

**Waitress starts but the site 404s on every page / static files missing**
- Make sure you run the Waitress command from inside the `CyberQuest-CTF` folder (the one containing `app.py`), the same as you would for `python app.py`.

**Countdown timer looks off**
- The timer resyncs with the server every 20 seconds and is always computed from server time — a participant's local clock cannot extend or shorten it.

---

## 15. Notes on Scope

This app is intended for a short, trusted, LAN-only college event and
intentionally keeps things simple (SQLite, in-memory rate limiting,
Flask's built-in dev server). For a larger or internet-facing
deployment you'd want a production WSGI server (e.g. Waitress on
Windows or gunicorn on Linux), HTTPS, and a more robust rate limiter —
none of which are necessary for a single-room event on a controlled
network.
