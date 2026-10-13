#!/usr/bin/env python3
"""victim-mail: webmail portal for the Email Hijacking lab.

Companion to legacy_auth.py (plaintext legacy mail-check on TCP 2323).
The demonstrated weakness is the unencrypted credential exchange, not
this code. Security events go to mail.log, which Labtainer checkwork
inspects (server-side evidence).
"""
import logging
import os
import secrets
import sqlite3
import time

from flask import Flask, redirect, request, session, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "mail.db")
# Outside any user HOME so the Labtainer artifact collector can package it.
LOG_PATH = os.environ.get("VICTIM_MAIL_LOG", "/var/log/victim-mail/mail.log")

VICTIM_USER = "victim"
VICTIM_PASS = "Vict1m_Mail!2026"
ATTACKER_USER = "attacker"
ATTACKER_PASS = "att4cker_Mail!2026"
# Id of the victim private message seeded below (used by checkwork docs).
PRIVATE_MAIL_ID = 2

app = Flask(__name__)
app.secret_key = "labtainer-email-hijacking-dev-key"
app.config["SESSION_COOKIE_HTTPONLY"] = True

handler = logging.FileHandler(LOG_PATH)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
event_log = logging.getLogger("victim-mail")
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
        "username TEXT PRIMARY KEY, password TEXT, role TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS mails("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, "
        "sender TEXT, subject TEXT, body TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS forwarding_rules("
        "user TEXT PRIMARY KEY, target_address TEXT, created_at REAL)"
    )
    if fresh:
        flag = "EMAIL_HIJACK_SUCCESS_" + secrets.token_hex(3)
        conn.execute(
            "INSERT INTO users(username, password, role) VALUES(?,?,?)",
            (VICTIM_USER, VICTIM_PASS, "employee"),
        )
        conn.execute(
            "INSERT INTO users(username, password, role) VALUES(?,?,?)",
            (ATTACKER_USER, ATTACKER_PASS, "guest"),
        )
        conn.executemany(
            "INSERT INTO mails(owner, sender, subject, body) VALUES(?,?,?,?)",
            [
                (VICTIM_USER, "hr@company.local", "Welcome aboard",
                 "Your employee mailbox is ready."),
                (VICTIM_USER, "boss@company.local", "Private: payroll token",
                 "Hi, your private payroll token is %s. "
                 "Do not forward this mail." % flag),
                (VICTIM_USER, "team@company.local", "Weekly meeting",
                 "Sync on Friday at 10:00."),
                (ATTACKER_USER, "hr@company.local", "Welcome",
                 "Guest mailbox. You cannot read employee mail."),
            ],
        )
        conn.commit()
    conn.close()


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


@app.route("/")
def index():
    user = current_user()
    if user:
        return (
            "<h1>Company webmail</h1>"
            "<p>Logged in as %s. <a href='/inbox'>Inbox</a></p>"
            "<form method='post' action='/logout'>"
            "<button type='submit'>Logout</button></form>" % user
        )
    return "<h1>Company webmail</h1><p><a href='/login'>Login</a></p>"


@app.route("/login", methods=["GET"])
def login_form():
    return (
        "<h1>Mailbox login</h1>"
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
        event_log.info("MAILBOX_LOGIN_SUCCESS user=%s src=%s", username, src)
        return redirect(url_for("inbox"))
    event_log.info("MAILBOX_LOGIN_FAIL user=%s src=%s", username, src)
    return ("<h1>Login failed</h1><p>Invalid credentials.</p>"
            "<a href='/login'>Try again</a>"), 401


@app.route("/inbox", methods=["GET"])
def inbox():
    user = current_user()
    if not user:
        return redirect(url_for("login_form"))
    conn = get_db()
    rows = conn.execute(
        "SELECT id, sender, subject FROM mails WHERE owner=? ORDER BY id",
        (user,),
    ).fetchall()
    conn.close()
    items = "".join(
        "<li><a href='/message?id=%d'>#%d %s — %s</a></li>"
        % (r["id"], r["id"], r["sender"], r["subject"]) for r in rows
    )
    return "<h1>Inbox (%s)</h1><ul>%s</ul>" % (user, items)


@app.route("/message", methods=["GET"])
def message():
    user = current_user()
    src = request.remote_addr
    if not user:
        return redirect(url_for("login_form"))
    try:
        mid = int(request.args.get("id", "0"))
    except ValueError:
        return "Bad id", 400
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM mails WHERE id=?", (mid,)
    ).fetchone()
    conn.close()
    if row is None or row["owner"] != user:
        event_log.info(
            "EMAIL_DENIED id=%d user=%s src=%s status=403", mid, user, src)
        return "<h1>Forbidden</h1><p>Not your mail.</p>", 403
    event_log.info(
        "EMAIL_READ id=%d user=%s src=%s status=200", mid, user, src)
    return ("<h1>%s</h1><p>From: %s</p><p>%s</p>"
            % (row["subject"], row["sender"], row["body"]))


@app.route("/send", methods=["POST"])
def send():
    user = current_user()
    src = request.remote_addr
    if not user:
        return redirect(url_for("login_form"))
    to = request.form.get("to", "")
    subject = request.form.get("subject", "")
    body = request.form.get("body", "")
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO mails(owner, sender, subject, body) VALUES(?,?,?,?)",
        (to, user + "@company.local", subject, body),
    )
    conn.commit()
    conn.close()
    event_log.info(
        "EMAIL_SENT id=%d from=%s to=%s src=%s", cur.lastrowid, user, to, src)
    return "<h1>Sent</h1><p>Mail id %d queued.</p>" % cur.lastrowid


@app.route("/forward", methods=["POST"])
def set_forward():
    # Mail forwarding rule: silently copies the owner's incoming mail to
    # an attacker-controlled address. The owner is ALWAYS taken from the
    # session (never from the request body) so a caller cannot set a rule
    # for somebody else. No real SMTP delivery exists in this lab; the
    # graded event is the rule creation itself, persisted in SQLite so it
    # survives logout/login (persistence of mailbox control).
    user = current_user()
    src = request.remote_addr
    if not user:
        return redirect(url_for("login_form"))
    target = request.form.get("target", "").strip()
    if not target:
        return "<h1>Bad request</h1><p>Missing target address.</p>", 400
    conn = get_db()
    conn.execute(
        "INSERT INTO forwarding_rules(user, target_address, created_at)"
        " VALUES(?,?,?)"
        " ON CONFLICT(user) DO UPDATE SET target_address=excluded.target_address,"
        " created_at=excluded.created_at",
        (user, target, time.time()),
    )
    conn.commit()
    conn.close()
    event_log.info(
        "FORWARD_RULE_SET user=%s src=%s target=%s", user, src, target)
    return ("<h1>Forwarding updated</h1>"
            "<p>All mail for %s will be forwarded to %s.</p>"
            % (user, target))


@app.route("/settings/forwarding", methods=["GET"])
def get_forward():
    user = current_user()
    src = request.remote_addr
    if not user:
        return redirect(url_for("login_form"))
    conn = get_db()
    row = conn.execute(
        "SELECT target_address FROM forwarding_rules WHERE user=?", (user,)
    ).fetchone()
    conn.close()
    target = row["target_address"] if row else "(none)"
    event_log.info(
        "FORWARD_RULE_VIEW user=%s src=%s status=200", user, src)
    return ("<h1>Forwarding settings</h1>"
            "<p>User: %s</p><p>Forward to: %s</p>" % (user, target))


@app.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    event_log.info("LOGOUT user=%s src=%s", user, request.remote_addr)
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000, threaded=True)
