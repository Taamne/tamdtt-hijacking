#!/usr/bin/env python3
"""victim-portal: token-auth portal for the Token Hijacking lab.

Auth model: on login the server mints a random bearer token, stores it
server-side (sessions table) and hands it to the client as an `auth`
cookie. Every request is authorized purely by presenting a valid token
-- whoever holds the token IS the user. A forgotten debug endpoint
(/debug/sessions) lists active tokens: that leak plus replay is the
demonstrated Token Hijacking technique. No password is ever needed by
the attacker. Security events go to portal.log (server-side evidence).
"""
import logging
import os
import secrets
import sqlite3
import time

from flask import Flask, redirect, request, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "portal.db")
# Outside any user HOME so the Labtainer artifact collector can package it.
LOG_PATH = os.environ.get("VICTIM_PORTAL_LOG", "/var/log/victim-portal/portal.log")

VICTIM_USER = "victim"
VICTIM_PASS = "Vict1m_Token!2026"
ATTACKER_USER = "attacker"
ATTACKER_PASS = "att4cker_Token!2026"

app = Flask(__name__)

handler = logging.FileHandler(LOG_PATH)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
event_log = logging.getLogger("victim-portal")
event_log.setLevel(logging.INFO)
event_log.addHandler(handler)
event_log.propagate = False


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    fresh = not os.path.exists(DB_PATH)
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users("
        "username TEXT PRIMARY KEY, password TEXT, role TEXT, note TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions("
        "token TEXT PRIMARY KEY, username TEXT, src TEXT, created REAL)"
    )
    if fresh:
        flag = "TOKEN_HIJACK_SUCCESS_" + secrets.token_hex(3)
        conn.execute(
            "INSERT INTO users(username, password, role, note) VALUES(?,?,?,?)",
            (VICTIM_USER, VICTIM_PASS, "employee", flag),
        )
        conn.execute(
            "INSERT INTO users(username, password, role, note) VALUES(?,?,?,?)",
            (ATTACKER_USER, ATTACKER_PASS, "guest",
             "Guest account. No access to employee private data."),
        )
        conn.commit()
    conn.close()


def mint_token(username, src):
    token = secrets.token_hex(16)
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions(token, username, src, created) VALUES(?,?,?,?)",
        (token, username, src, time.time()),
    )
    conn.commit()
    conn.close()
    event_log.info("TOKEN_ISSUED user=%s src=%s", username, src)
    return token


def lookup_token(token):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM sessions WHERE token=?", (token,)
    ).fetchone()
    conn.close()
    return row


@app.before_request
def audit_access():
    tok = request.cookies.get("auth", "-")
    short = (tok[:8] + "..") if len(tok) > 10 else tok
    event_log.info(
        "%s %s src=%s token=%s",
        request.method, request.path, request.remote_addr, short,
    )


@app.route("/")
def index():
    return ("<h1>Employee portal</h1>"
            "<p><a href='/login'>Login</a></p>"
            "<p><a href='/profile'>Profile</a> (needs token)</p>")


@app.route("/login", methods=["GET"])
def login_form():
    return (
        "<h1>Login</h1>"
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
        token = mint_token(username, src)
        resp = redirect(url_for("profile"))
        resp.set_cookie("auth", token, httponly=True)
        return resp
    event_log.info("TOKEN_LOGIN_FAIL user=%s src=%s", username, src)
    return ("<h1>Login failed</h1><p>Invalid credentials.</p>"
            "<a href='/login'>Try again</a>"), 401


@app.route("/profile", methods=["GET"])
def profile():
    token = request.cookies.get("auth", "")
    src = request.remote_addr
    sess = lookup_token(token) if token else None
    if sess is None:
        event_log.info("PROFILE_DENIED src=%s status=401", src)
        return redirect(url_for("login_form"))
    user = sess["username"]
    # Replay detection: token first seen from another IP.
    if sess["src"] != src:
        event_log.info(
            "TOKEN_REPLAY user=%s src=%s orig_src=%s", user, src, sess["src"])
        via = "replay"
    else:
        via = "direct"
    conn = get_db()
    row = conn.execute(
        "SELECT username, role, note FROM users WHERE username=?", (user,)
    ).fetchone()
    conn.close()
    event_log.info(
        "PROFILE_ACCESS user=%s src=%s via=%s status=200", user, src, via)
    return ("<h1>Profile</h1>"
            "<p>Username: %s</p><p>Role: %s</p>"
            "<p>Private note: %s</p>"
            % (row["username"], row["role"], row["note"]))


@app.route("/debug/sessions", methods=["GET"])
def debug_sessions():
    # Forgotten diagnostic endpoint: lists every active bearer token.
    # THIS is the leak exploited in this lab.
    src = request.remote_addr
    event_log.info("DEBUG_ACCESS src=%s", src)
    conn = get_db()
    rows = conn.execute("SELECT username, token FROM sessions").fetchall()
    conn.close()
    return {r["username"]: r["token"] for r in rows}


@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("auth", "")
    if token:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        event_log.info("LOGOUT src=%s", request.remote_addr)
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000, threaded=True)
