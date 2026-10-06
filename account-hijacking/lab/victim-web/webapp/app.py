#!/usr/bin/env python3
"""victim-web: legacy customer portal for Account Hijacking lab.

Intentionally simple Flask app. The vulnerability demonstrated by this lab
is NOT in this code -- it is the leaked credential stored in a stale
backup file on the attacker container. This app just behaves like a
normal session-based portal and records security-relevant events to
app.log, which Labtainer checkwork inspects.
"""
import logging
import os
import secrets
import sqlite3

from flask import Flask, redirect, request, session, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "victim.db")
# Primary audit log lives outside any user HOME so that the Labtainer
# artifact collector can package it (files under /home/<user> whose
# absolute path re-contains that prefix are skipped by the packager).
LOG_PATH = os.environ.get("VICTIM_LOG", "/var/log/victim-web/app.log")

# Web login accounts for the lab (mirror of the leaked backup artifact).
VICTIM_USER = "victim"
VICTIM_PASS = "Vict1m_Summer!2026"
ATTACKER_USER = "attacker"
ATTACKER_PASS = "att4cker_Guest!2026"

app = Flask(__name__)
# Static signing key is fine for an isolated teaching lab.
app.secret_key = "labtainer-account-hijacking-dev-key"
app.config["SESSION_COOKIE_HTTPONLY"] = True

handler = logging.FileHandler(LOG_PATH)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
event_log = logging.getLogger("victim-web")
event_log.setLevel(logging.INFO)
event_log.addHandler(handler)
event_log.propagate = False


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create and seed the database on first boot.

    The victim private note carries a random suffix generated here, so the
    full flag value never appears in the lab sources and cannot be found
    by grepping the repository.
    """
    fresh = not os.path.exists(DB_PATH)
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users("
        "username TEXT PRIMARY KEY, password TEXT, role TEXT, note TEXT)"
    )
    if fresh:
        flag = "ACCOUNT_HIJACK_SUCCESS_" + secrets.token_hex(3)
        conn.execute(
            "INSERT INTO users(username, password, role, note) VALUES(?,?,?,?)",
            (VICTIM_USER, VICTIM_PASS, "employee", flag),
        )
        conn.execute(
            "INSERT INTO users(username, password, role, note) VALUES(?,?,?,?)",
            (
                ATTACKER_USER,
                ATTACKER_PASS,
                "guest",
                "Guest account. No access to employee private data.",
            ),
        )
        conn.commit()
    conn.close()


# Stale backup artifact, intentionally exposed (simulates a forgotten
# backup file left reachable on the portal -- the credential leak at
# the heart of this lab). The path is NOT documented in the manual;
# students must discover it, e.g. by inspecting page sources.
BACKUP_PATH = "/old/portal_backup_2024_old.txt"
BACKUP_BODY = """# Archived portal backup -- 2024-11-02
# ---------------------------------------------------------------
# Legacy customer portal (decommissioned Jan 2025, moved to vault).
# These debug credentials were only used by the old staging portal.
# TODO(owner): delete this file, rotation tracked in ticket OPS-1187.
#
portal_user = victim
portal_pass = Vict1m_Summer!2026
#
# NOTE: staging portal is offline, do NOT reuse these anywhere.
"""

HINT_COMMENT = "<!-- legacy backup removed before prod? check %s -->" % BACKUP_PATH


def current_user():
    return session.get("user")


@app.before_request
def audit_access():
    event_log.info(
        "%s %s src=%s user=%s",
        request.method,
        request.path,
        request.remote_addr,
        current_user() or "-",
    )


@app.route(BACKUP_PATH)
def stale_backup():
    return BACKUP_BODY, 200, {"Content-Type": "text/plain"}


@app.route("/")
def index():
    user = current_user()
    if user:
        return (
            "<h1>Customer portal</h1>"
            "<p>Logged in as %s. <a href='/profile'>Profile</a></p>"
            "<form method='post' action='/logout'>"
            "<button type='submit'>Logout</button></form>" % user
        )
    return (
        "<h1>Customer portal</h1>" + HINT_COMMENT +
        "<p><a href='/login'>Login</a></p>"
    )


@app.route("/login", methods=["GET"])
def login_form():
    return (
        "<h1>Login</h1>" + HINT_COMMENT +
        "<form method='post' action='/login'>"
        "Username: <input name='username'/><br/>"
        "Password: <input type='password' name='password'/><br/>"
        "<button type='submit'>Login</button></form>"
    )


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    src = request.remote_addr
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if row and row["password"] == password:
        session["user"] = username
        event_log.info("LOGIN_SUCCESS user=%s src=%s", username, src)
        return redirect(url_for("profile"))
    event_log.info("LOGIN_FAIL user=%s src=%s", username, src)
    return ("<h1>Login failed</h1><p>Invalid credentials.</p>"
            "<a href='/login'>Try again</a>"), 401


@app.route("/profile", methods=["GET"])
def profile():
    user = current_user()
    src = request.remote_addr
    if not user:
        event_log.info("PROFILE_DENIED user=- src=%s status=401", src)
        return redirect(url_for("login_form"))
    conn = get_db()
    row = conn.execute(
        "SELECT username, role, note FROM users WHERE username=?", (user,)
    ).fetchone()
    conn.close()
    event_log.info("PROFILE_ACCESS user=%s src=%s status=200", user, src)
    return (
        "<h1>Profile</h1>"
        "<p>Username: %s</p><p>Role: %s</p>"
        "<p>Private note: %s</p>" % (row["username"], row["role"], row["note"])
    )


@app.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    event_log.info("LOGOUT user=%s src=%s", user, request.remote_addr)
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    # Port 8000: unprivileged, no root needed inside the container.
    app.run(host="0.0.0.0", port=8000, threaded=True)
