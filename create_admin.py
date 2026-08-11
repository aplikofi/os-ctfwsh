"""
create_admin.py
================
Command-line utility to create (or update) an organizer/admin account.

Usage:
    python create_admin.py
    python create_admin.py --username organizer

You will be prompted for a password (input is hidden). This never
hard-codes a password anywhere in the project — it's only ever entered
interactively or via the ADMIN_PASSWORD environment variable.
"""

import argparse
import getpass
import os
import sys

from werkzeug.security import generate_password_hash

from app import app
from db import get_db, init_db, now_iso


def main():
    parser = argparse.ArgumentParser(description="Create or update a CyberQuest CTF admin account.")
    parser.add_argument("--username", help="Admin username", default=None)
    args = parser.parse_args()

    username = args.username or os.environ.get("ADMIN_USERNAME")
    if not username:
        username = input("Admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)

    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            sys.exit(1)

    if len(password) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)

    with app.app_context():
        init_db(app)
        db = get_db()
        existing = db.execute(
            "SELECT id FROM admins WHERE username = ?", (username,)
        ).fetchone()

        password_hash = generate_password_hash(password)

        if existing:
            db.execute(
                "UPDATE admins SET password_hash = ? WHERE username = ?",
                (password_hash, username),
            )
            db.commit()
            print(f"Updated password for existing admin '{username}'.")
        else:
            db.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, now_iso()),
            )
            db.commit()
            print(f"Admin account '{username}' created successfully.")

        db.close()


if __name__ == "__main__":
    main()
