#!/usr/bin/env python3
"""DATN Portal - demo target for the identity & session hijacking lab.

This single FastAPI service combines:
  * employee portal login (web session cookie + CSRF token)
  * profile / password management
  * a small webmail (inbox, sent, compose, forwarding rule)
  * JWT bearer API (/api/token, /api/me, /api/mailbox/summary)
  * a forgotten /debug/sessions endpoint that leaks live sessions/tokens
  * a JSONL audit log at /var/log/datn/app.jsonl

The lab deliberately runs in "baseline" mode: changing a password does NOT
revoke existing web sessions or JWTs, so an attacker who already stole a
token keeps access.  Hardened mode is available for comparison.

No password, raw token, Authorization header or cookie value is ever
written to the audit log.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATN_DB", os.path.join(APP_DIR, "datn.db"))
LOG_PATH = os.environ.get("DATN_LOG", "/var/log/datn/app.jsonl")
BACKUP_PATH = os.path.join(APP_DIR, "backup", "users.csv")

SERVICE = "datn-portal"
SCHEMA_VERSION = "1.0"
JWT_SECRET = os.environ.get("DATN_JWT_SECRET", "datn-lab-demo-secret-v1")
JWT_ISS = "datn-portal"
JWT_AUD = "datn-api"
SESSION_TTL = 8 * 3600
TOKEN_TTL = 8 * 3600
PASSWORD_ITERATIONS = 120000
SESSION_COOKIE = "datn_session"
CSRF_COOKIE = "datn_csrf"

# Seeded demo accounts.  The leaked backup file contains the same plaintext
# passwords, which is exactly the credential-compromise step of the demo.
SEED_USERS = [
    ("user01@datn.local", "Us3r01_DATN!2026", "user", "+84-900-111-001"),
    ("attacker@datn.local", "Att4ck3r_DATN!2026", "user", "+84-900-222-002"),
    ("admin@datn.local", "Adm1n_DATN!2026", "admin", "+84-900-000-000"),
]

SEED_MAILS = [
    ("user01@datn.local", "hr@datn.local", "Welcome aboard",
     "Your employee mailbox is ready. Please complete your profile."),
    ("user01@datn.local", "finance@datn.local", "Payroll verification code",
     "Your private payroll verification code is PAYROLL-USER01-2026. "
     "Do not share it with anyone."),
    ("user01@datn.local", "team@datn.local", "Weekly sync",
     "Reminder: team sync on Friday at 10:00 in room 3A."),
    ("attacker@datn.local", "hr@datn.local", "Guest account",
     "This is the guest mailbox. It has no access to employee data."),
    ("admin@datn.local", "security@datn.local", "Admin notice",
     "Please review the portal audit log weekly."),
]

# Approved forwarding rules (baseline inventory). The monitor compares the
# live rules against this list; the attacker's B3 rule is the unapproved one.
SEED_RULES = [
    ("user01@datn.local", "user01.archive@datn.local"),
    ("admin@datn.local", "assistant@datn.local"),
]

app = FastAPI(title="DATN Portal", docs_url=None, redoc_url=None)
log_lock = threading.Lock()

BASE_STYLE = """
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #f4f6f8; color: #1f2933; }
  nav { background: #102a43; color: #fff; padding: 12px 22px; display: flex;
        align-items: center; gap: 18px; flex-wrap: wrap; }
  nav a { color: #d9e2ec; text-decoration: none; }
  nav a:hover { color: #fff; }
  nav .spacer { flex: 1; }
  nav button { background: #243b53; color: #fff; border: 0; padding: 7px 12px;
               border-radius: 6px; cursor: pointer; }
  main { max-width: 980px; margin: 28px auto; padding: 0 18px; }
  h1 { margin-top: 0; }
  .card { background: #fff; border: 1px solid #d9e2ec; border-radius: 10px;
          padding: 18px 20px; margin: 14px 0; box-shadow: 0 1px 2px rgba(16,42,67,.06); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
  label { display: block; margin: 10px 0 4px; font-weight: 600; }
  input[type=text], input[type=password], input[type=email], textarea {
      width: 100%; padding: 9px 10px; border: 1px solid #bcccdc; border-radius: 6px;
      font: inherit; }
  textarea { resize: vertical; }
  button.primary { background: #0b69a3; color: #fff; border: 0; padding: 10px 16px;
                   border-radius: 6px; cursor: pointer; font: inherit; margin-top: 12px; }
  button.primary:hover { background: #095a8c; }
  .muted { color: #627d98; }
  .error { background: #ffe3e3; border: 1px solid #ffbdbd; color: #8a1c1c;
           padding: 10px 12px; border-radius: 6px; }
  .ok { background: #e3f9e5; border: 1px solid #a7e3ad; color: #1b5e20;
        padding: 10px 12px; border-radius: 6px; }
  ul.mail { list-style: none; padding: 0; }
  ul.mail li { padding: 10px 0; border-bottom: 1px solid #e6edf3; }
  ul.mail a { color: #0b69a3; text-decoration: none; }
  pre { white-space: pre-wrap; background: #f0f4f8; padding: 14px; border-radius: 8px; }
  .check { font-weight: 400; display: flex; gap: 8px; align-items: center; }
  .tag { display: inline-block; background: #e6edf3; border-radius: 999px;
         padding: 2px 9px; font-size: 12px; color: #334e68; }
</style>
"""


def utc_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def now_ts():
    return time.time()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt_hex=None):
    salt_hex = salt_hex or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex),
        PASSWORD_ITERATIONS,
    )
    return salt_hex, digest.hex()


def verify_password(password, salt_hex, expected_hex):
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex),
        PASSWORD_ITERATIONS,
    )
    return hmac.compare_digest(digest.hex(), expected_hex)


def init_db():
    conn = db()
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users("
            "email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, "
            "salt TEXT NOT NULL, role TEXT NOT NULL, phone TEXT, "
            "created_at REAL NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions("
            "sid TEXT PRIMARY KEY, jti TEXT NOT NULL, user_id TEXT NOT NULL, "
            "csrf TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL, "
            "src_ip TEXT, user_agent TEXT, mail_login_sent INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens("
            "jti TEXT PRIMARY KEY, user_id TEXT NOT NULL, role TEXT NOT NULL, "
            "token TEXT NOT NULL, issued_at REAL NOT NULL, expires_at REAL NOT NULL, "
            "issued_src TEXT, revoked INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS mails("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, "
            "sender TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, "
            "created_at REAL NOT NULL, forwarded INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS forwarding_rules("
            "user_id TEXT PRIMARY KEY, target_address TEXT NOT NULL, "
            "created_at REAL NOT NULL)"
        )
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if user_count == 0:
            for email, password, role, phone in SEED_USERS:
                salt, digest = hash_password(password)
                conn.execute(
                    "INSERT INTO users(email, password_hash, salt, role, phone, "
                    "created_at) VALUES(?,?,?,?,?,?)",
                    (email, digest, salt, role, phone, now_ts()),
                )
        mail_count = conn.execute("SELECT COUNT(*) AS c FROM mails").fetchone()["c"]
        if mail_count == 0:
            conn.executemany(
                "INSERT INTO mails(owner, sender, subject, body, created_at) "
                "VALUES(?,?,?,?,?)",
                [(owner, sender, subject, body, now_ts())
                 for owner, sender, subject, body in SEED_MAILS],
            )
        # Seed the approved baseline forwarding inventory. INSERT OR IGNORE
        # keeps a rule that the demo already changed (e.g. after a redo of
        # only the app) from being silently restored.
        for user_id, target in SEED_RULES:
            conn.execute(
                "INSERT OR IGNORE INTO forwarding_rules(user_id, "
                "target_address, created_at) VALUES(?,?,?)",
                (user_id, target, now_ts()),
            )
        conn.commit()
    finally:
        conn.close()


def ensure_log_dir():
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    except OSError:
        pass


def client_ip(request):
    return request.client.host if request.client else "-"


def log_event(request, event_type, category, severity="info", result="success",
              user_id=None, jti=None, extra=None):
    event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": "evt-" + uuid.uuid4().hex,
        "timestamp": utc_iso(),
        "service": SERVICE,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "result": result,
        "src_ip": client_ip(request) if request is not None else "-",
        "user_agent": (request.headers.get("user-agent", "-") if request else "-")[:200],
        "request_id": (getattr(request.state, "request_id", None) if request else None)
        or ("req-" + uuid.uuid4().hex),
    }
    if user_id:
        event["user_id"] = user_id
    if jti:
        event["jti"] = jti
    if extra:
        for key, value in extra.items():
            if value is not None:
                event[key] = value
    line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
    ensure_log_dir()
    with log_lock:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


@app.middleware("http")
async def request_id_middleware(request, call_next):
    request.state.request_id = (
        request.headers.get("x-request-id") or "req-" + uuid.uuid4().hex
    )
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


async def form_data(request):
    body = await request.body()
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = json.loads(body.decode("utf-8") or "{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, UnicodeDecodeError):
            return {}
    try:
        parsed = urllib.parse.parse_qs(
            body.decode("utf-8"), keep_blank_values=True
        )
        return {key: values[0] for key, values in parsed.items()}
    except (ValueError, UnicodeDecodeError):
        return {}


def normalize_email(value):
    value = (value or "").strip().lower()
    if value and "@" not in value:
        value += "@datn.local"
    return value


def check_csrf(request, session, form):
    """Same-origin browser POSTs must carry the per-session CSRF token.

    curl/CLI clients do not send an Origin header, so the demo commands in
    the lab manual keep working without token plumbing.
    """
    origin = request.headers.get("origin")
    if origin:
        allowed = "http://" + request.headers.get("host", "")
        if origin.rstrip("/") != allowed.rstrip("/"):
            return False
    token = form.get("csrf_token") or request.headers.get("x-csrf-token")
    if token and session:
        if not hmac.compare_digest(str(token), str(session["csrf"])):
            return False
    return True


def get_session(request):
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    conn = db()
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE sid=?", (sid,)
        ).fetchone()
        if row is None:
            return None
        if float(row["created_at"]) + SESSION_TTL < time.time():
            conn.execute("DELETE FROM sessions WHERE sid=?", (sid,))
            conn.commit()
            return None
        conn.execute(
            "UPDATE sessions SET last_seen=? WHERE sid=?", (now_ts(), sid)
        )
        conn.commit()
        return dict(row)
    finally:
        conn.close()


def get_user(conn, email):
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return dict(row) if row else None


def get_forwarding_rule(conn, email):
    row = conn.execute(
        "SELECT target_address FROM forwarding_rules WHERE user_id=?", (email,)
    ).fetchone()
    return row["target_address"] if row else None


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwt_encode(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    head = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    body = b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing = (head + "." + body).encode("ascii")
    sig = hmac.new(JWT_SECRET.encode("utf-8"), signing, hashlib.sha256).digest()
    return head + "." + body + "." + b64url(sig)


def jwt_check(token):
    """Return (payload, reason). reason is None for a usable token."""
    try:
        head, body, sig = token.split(".")
    except ValueError:
        return None, "malformed_token"
    signing = (head + "." + body).encode("ascii")
    expected = b64url(
        hmac.new(JWT_SECRET.encode("utf-8"), signing, hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig, expected):
        return None, "invalid_signature"
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
        )
    except (ValueError, UnicodeDecodeError):
        return None, "malformed_payload"
    if payload.get("iss") != JWT_ISS or payload.get("aud") != JWT_AUD:
        return payload, "invalid_claims"
    try:
        expires_at = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        return payload, "invalid_claims"
    if expires_at < int(time.time()):
        return payload, "expired"
    jti = payload.get("jti")
    if not jti:
        return payload, "missing_jti"
    conn = db()
    try:
        row = conn.execute("SELECT * FROM tokens WHERE jti=?", (jti,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return payload, "unknown_token"
    if int(row["revoked"]) != 0:
        return payload, "revoked"
    if row["user_id"] != payload.get("sub"):
        return payload, "subject_mismatch"
    return payload, None


def authenticate_bearer(request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, "missing_token"
    token = auth.split(None, 1)[1].strip()
    if not token:
        return None, "missing_token"
    return jwt_check(token)


def nav_html(session):
    if not session:
        return ""
    csrf = html.escape(session["csrf"])
    user = html.escape(session["user_id"])
    return (
        "<nav><b>DATN Portal</b>"
        "<a href='/'>Home</a>"
        "<a href='/profile'>Profile</a>"
        "<a href='/mail/inbox'>Mailbox</a>"
        "<span class='spacer'></span>"
        "<span>" + user + "</span>"
        "<form method='post' action='/logout' style='display:inline;margin:0'>"
        "<input type='hidden' name='csrf_token' value='" + csrf + "'>"
        "<button type='submit'>Sign out</button></form></nav>"
    )


def page(title, body, session=None, status_code=200):
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>" + html.escape(title) + " - DATN Portal</title>"
        + BASE_STYLE + "</head><body>" + nav_html(session)
        + "<main>" + body + "</main></body></html>",
        status_code=status_code,
    )


LOGIN_BODY = """
<h1>DATN Portal</h1>
<p class='muted'>Internal employee portal. Sign in to continue.</p>
<form method='post' action='/login' class='card'>
  <label for='username'>Email</label>
  <input id='username' name='username' autocomplete='username' autofocus>
  <label for='password'>Password</label>
  <input id='password' type='password' name='password' autocomplete='current-password'>
  <button class='primary' type='submit'>Sign in</button>
</form>
"""


def profile_body(session, user):
    csrf = html.escape(session["csrf"])
    email = html.escape(user["email"])
    role = html.escape(user["role"] or "")
    phone = html.escape(user["phone"] or "")
    return """
<h1>Profile</h1>
<div class='grid'>
  <div class='card'>
    <h2>Account</h2>
    <p><b>Email:</b> %s<br><b>Role:</b> <span class='tag'>%s</span></p>
    <form method='post' action='/profile'>
      <input type='hidden' name='csrf_token' value='%s'>
      <label for='phone'>Phone</label>
      <input id='phone' name='phone' value='%s'>
      <button class='primary' type='submit'>Save profile</button>
    </form>
  </div>
  <div class='card'>
    <h2>Password</h2>
    <form method='post' action='/password'>
      <input type='hidden' name='csrf_token' value='%s'>
      <label for='current_password'>Current password</label>
      <input id='current_password' type='password' name='current_password'>
      <label for='new_password'>New password</label>
      <input id='new_password' type='password' name='new_password'>
      <label class='check'><input type='checkbox' name='hardened' value='1'>
        Hardened mode: revoke all sessions and API tokens</label>
      <button class='primary' type='submit'>Change password</button>
    </form>
  </div>
  <div class='card'>
    <h2>API</h2>
    <p>Issue a JWT bearer token for the DATN API.</p>
    <form method='post' action='/api/token'>
      <input type='hidden' name='csrf_token' value='%s'>
      <button class='primary' type='submit'>Issue API token</button>
    </form>
    <p><a href='/mail/inbox'>Open mailbox</a></p>
  </div>
</div>
""" % (email, role, csrf, phone, csrf, csrf)


def mail_nav():
    return (
        "<p><a href='/mail/inbox'>Inbox</a> | "
        "<a href='/mail/sent'>Sent</a> | "
        "<a href='/mail/compose'>Compose</a> | "
        "<a href='/mail/settings/forwarding'>Forwarding settings</a> | "
        "<a href='/profile'>Profile</a></p>"
    )


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (TypeError, ValueError, OSError):
        return "-"


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    session = get_session(request)
    if session:
        body = (
            "<h1>DATN Portal</h1><p>Signed in as <b>"
            + html.escape(session["user_id"])
            + "</b>.</p><p><a href='/profile'>Profile</a> | "
            "<a href='/mail/inbox'>Mailbox</a></p>"
        )
        return page("Home", body, session)
    return page(
        "Home",
        "<h1>DATN Portal</h1><p>Internal employee portal.</p>"
        "<p><a href='/login'>Sign in</a></p>",
    )


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if get_session(request):
        return RedirectResponse("/profile", status_code=303)
    return page("Sign in", LOGIN_BODY)


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    form = await form_data(request)
    username = normalize_email(form.get("username", ""))
    password = str(form.get("password", ""))
    conn = db()
    try:
        user = get_user(conn, username)
    finally:
        conn.close()
    if user and verify_password(password, user["salt"], user["password_hash"]):
        sid = secrets.token_urlsafe(32)
        jti = "sess-" + uuid.uuid4().hex
        csrf = secrets.token_urlsafe(24)
        conn = db()
        try:
            conn.execute(
                "INSERT INTO sessions(sid, jti, user_id, csrf, created_at, "
                "last_seen, src_ip, user_agent) VALUES(?,?,?,?,?,?,?,?)",
                (sid, jti, username, csrf, now_ts(), now_ts(), client_ip(request),
                 request.headers.get("user-agent", "-")[:200]),
            )
            conn.commit()
        finally:
            conn.close()
        log_event(
            request, "login_success", "auth", "info", "success",
            user_id=username, jti=jti,
            extra={"session_type": "web", "method": "password"},
        )
        response = RedirectResponse("/profile", status_code=303)
        response.set_cookie(
            SESSION_COOKIE, sid, max_age=SESSION_TTL, httponly=True,
            samesite="strict", path="/",
        )
        response.set_cookie(
            CSRF_COOKIE, csrf, max_age=SESSION_TTL, httponly=False,
            samesite="strict", path="/",
        )
        return response
    log_event(
        request, "login_failed", "auth", "warning", "failure",
        user_id=username or None,
        extra={"reason": "bad_credentials"},
    )
    body = (
        "<h1>DATN Portal</h1>"
        "<p class='error'>Invalid email or password.</p>"
        + LOGIN_BODY.split("</h1>", 1)[1]
    )
    return page("Sign in", body, None, status_code=401)


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    try:
        user = get_user(conn, session["user_id"])
    finally:
        conn.close()
    if not user:
        return RedirectResponse("/login", status_code=303)
    return page("Profile", profile_body(session, user), session)


@app.post("/profile", response_class=HTMLResponse)
async def update_profile(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await form_data(request)
    if not check_csrf(request, session, form):
        log_event(
            request, "profile_updated", "account", "warning", "denied",
            user_id=session["user_id"], jti=session["jti"],
            extra={"reason": "csrf"},
        )
        return page("Forbidden", "<h1>Forbidden</h1><p>Bad CSRF token.</p>",
                    session, status_code=403)
    phone = str(form.get("phone", "")).strip()[:64]
    conn = db()
    try:
        conn.execute(
            "UPDATE users SET phone=? WHERE email=?",
            (phone, session["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()
    log_event(
        request, "profile_updated", "account", "info", "success",
        user_id=session["user_id"], jti=session["jti"],
        extra={"fields": ["phone"]},
    )
    return RedirectResponse("/profile", status_code=303)


@app.post("/password", response_class=HTMLResponse)
async def change_password(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await form_data(request)
    if not check_csrf(request, session, form):
        log_event(
            request, "password_changed", "account", "warning", "denied",
            user_id=session["user_id"], jti=session["jti"],
            extra={"reason": "csrf"},
        )
        return page("Forbidden", "<h1>Forbidden</h1><p>Bad CSRF token.</p>",
                    session, status_code=403)
    current_password = str(form.get("current_password", ""))
    new_password = str(form.get("new_password", ""))
    hardened = str(form.get("hardened", "0")).lower() in ("1", "true", "yes", "on")
    if not current_password or not new_password:
        return page("Password", "<h1>Password</h1><p class='error'>"
                    "Both current and new password are required.</p>",
                    session, status_code=400)
    conn = db()
    try:
        user = get_user(conn, session["user_id"])
        if not user or not verify_password(
                current_password, user["salt"], user["password_hash"]):
            log_event(
                request, "password_changed", "account", "warning", "failure",
                user_id=session["user_id"], jti=session["jti"],
                extra={"reason": "bad_current_password", "hardened": hardened},
            )
            return page("Password", "<h1>Password</h1><p class='error'>"
                        "Current password is incorrect.</p>",
                        session, status_code=403)
        salt, digest = hash_password(new_password)
        conn.execute(
            "UPDATE users SET password_hash=?, salt=? WHERE email=?",
            (digest, salt, session["user_id"]),
        )
        revoked_sessions = 0
        revoked_tokens = 0
        if hardened:
            cur = conn.execute(
                "DELETE FROM sessions WHERE user_id=?", (session["user_id"],)
            )
            revoked_sessions = cur.rowcount
            cur = conn.execute(
                "UPDATE tokens SET revoked=1 WHERE user_id=? AND revoked=0",
                (session["user_id"],),
            )
            revoked_tokens = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    log_event(
        request, "password_changed", "account",
        "info" if hardened else "warning", "success",
        user_id=session["user_id"], jti=session["jti"],
        extra={"hardened": hardened, "revoked_sessions": revoked_sessions,
               "revoked_tokens": revoked_tokens},
    )
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({
            "status": "ok",
            "hardened": hardened,
            "revoked_sessions": revoked_sessions,
            "revoked_tokens": revoked_tokens,
        })
    if hardened:
        response = page(
            "Password changed",
            "<h1>Password changed</h1><p class='ok'>Hardened mode: all sessions "
            "and API tokens were revoked.</p><p><a href='/login'>Sign in again</a></p>",
        )
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(CSRF_COOKIE, path="/")
        return response
    return page(
        "Password changed",
        "<h1>Password changed</h1><p class='ok'>Baseline mode: existing web "
        "sessions and API tokens were <b>not</b> revoked.</p>"
        "<p><a href='/profile'>Back to profile</a></p>",
        session,
    )


def _mail_login_once(request, session, conn):
    if int(session.get("mail_login_sent", 0)) == 0:
        conn.execute(
            "UPDATE sessions SET mail_login_sent=1 WHERE sid=?", (session["sid"],)
        )
        conn.commit()
        log_event(
            request, "mail_login", "mail", "info", "success",
            user_id=session["user_id"], jti=session["jti"],
            extra={"mailbox": session["user_id"]},
        )


@app.get("/mail/inbox", response_class=HTMLResponse)
def mail_inbox(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    try:
        _mail_login_once(request, session, conn)
        rows = conn.execute(
            "SELECT id, sender, subject, created_at FROM mails "
            "WHERE owner=? ORDER BY id DESC", (session["user_id"],)
        ).fetchall()
    finally:
        conn.close()
    if rows:
        items = "".join(
            "<li><a href='/mail/message/%d'>#%d %s &mdash; %s</a> "
            "<span class='muted'>(%s)</span></li>"
            % (r["id"], r["id"], html.escape(r["sender"]),
               html.escape(r["subject"]), fmt_time(r["created_at"]))
            for r in rows
        )
    else:
        items = "<li class='muted'>No messages.</li>"
    body = (
        "<h1>Inbox</h1>" + mail_nav()
        + "<div class='card'><ul class='mail'>" + items + "</ul></div>"
    )
    return page("Inbox", body, session)


@app.get("/mail/sent", response_class=HTMLResponse)
def mail_sent(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, owner, subject, created_at FROM mails "
            "WHERE sender=? ORDER BY id DESC", (session["user_id"],)
        ).fetchall()
    finally:
        conn.close()
    if rows:
        items = "".join(
            "<li>#%d to %s &mdash; %s <span class='muted'>(%s)</span></li>"
            % (r["id"], html.escape(r["owner"]), html.escape(r["subject"]),
               fmt_time(r["created_at"]))
            for r in rows
        )
    else:
        items = "<li class='muted'>No sent messages.</li>"
    body = (
        "<h1>Sent</h1>" + mail_nav()
        + "<div class='card'><ul class='mail'>" + items + "</ul></div>"
    )
    return page("Sent", body, session)


@app.get("/mail/message/{message_id}", response_class=HTMLResponse)
def mail_message(request: Request, message_id: int):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    try:
        row = conn.execute(
            "SELECT * FROM mails WHERE id=?", (message_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None or row["owner"] != session["user_id"]:
        log_event(
            request, "mail_read", "mail", "warning", "denied",
            user_id=session["user_id"], jti=session["jti"],
            extra={"mailbox": session["user_id"], "message_id": message_id},
        )
        return page("Forbidden", "<h1>Forbidden</h1><p>Not your mail.</p>",
                    session, status_code=403)
    log_event(
        request, "mail_read", "mail", "info", "success",
        user_id=session["user_id"], jti=session["jti"],
        extra={"mailbox": session["user_id"], "message_id": message_id,
               "sender": row["sender"]},
    )
    body = (
        "<h1>" + html.escape(row["subject"]) + "</h1>" + mail_nav()
        + "<div class='card'><p><b>From:</b> " + html.escape(row["sender"])
        + "<br><b>To:</b> " + html.escape(row["owner"])
        + "<br><b>Date:</b> " + fmt_time(row["created_at"]) + "</p>"
        + "<pre>" + html.escape(row["body"]) + "</pre></div>"
    )
    return page("Message", body, session)


@app.get("/mail/compose", response_class=HTMLResponse)
def mail_compose(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    csrf = html.escape(session["csrf"])
    body = (
        "<h1>Compose</h1>" + mail_nav()
        + "<form method='post' action='/mail/send' class='card'>"
        "<input type='hidden' name='csrf_token' value='" + csrf + "'>"
        "<label for='to'>To</label>"
        "<input id='to' name='to' value='user01@datn.local'>"
        "<label for='subject'>Subject</label>"
        "<input id='subject' name='subject'>"
        "<label for='body'>Body</label>"
        "<textarea id='body' name='body' rows='8'></textarea>"
        "<button class='primary' type='submit'>Send message</button></form>"
    )
    return page("Compose", body, session)


@app.post("/mail/send", response_class=HTMLResponse)
async def mail_send(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await form_data(request)
    if not check_csrf(request, session, form):
        return page("Forbidden", "<h1>Forbidden</h1><p>Bad CSRF token.</p>",
                    session, status_code=403)
    to_addr = normalize_email(form.get("to", ""))
    subject = str(form.get("subject", "")).strip() or "(no subject)"
    body_text = str(form.get("body", ""))
    if not to_addr:
        return page("Compose", "<h1>Compose</h1><p class='error'>"
                    "Recipient is required.</p>", session, status_code=400)
    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO mails(owner, sender, subject, body, created_at) "
            "VALUES(?,?,?,?,?)",
            (to_addr, session["user_id"], subject, body_text, now_ts()),
        )
        message_id = cur.lastrowid
        rule = get_forwarding_rule(conn, to_addr)
        forwarded_id = None
        if rule:
            cur = conn.execute(
                "INSERT INTO mails(owner, sender, subject, body, created_at, "
                "forwarded) VALUES(?,?,?,?,?,1)",
                (rule, session["user_id"], "[FWD] " + subject, body_text, now_ts()),
            )
            forwarded_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    log_event(
        request, "mail_sent", "mail", "info", "success",
        user_id=session["user_id"], jti=session["jti"],
        extra={"mailbox": to_addr, "message_id": message_id,
               "subject": subject},
    )
    if rule:
        log_event(
            request, "mail_forwarded", "mail", "warning", "success",
            user_id=to_addr, jti=session["jti"],
            extra={"mailbox": to_addr, "rule": rule, "target": rule,
                   "original_message_id": message_id,
                   "forwarded_message_id": forwarded_id},
        )
    note = ""
    if rule:
        note = ("<p class='ok'>A forwarding rule was active: the message was "
                "also copied to <b>" + html.escape(rule) + "</b>.</p>")
    return page(
        "Sent",
        "<h1>Message sent</h1><p>Message #%d delivered to %s.</p>%s"
        % (message_id, html.escape(to_addr), note) + mail_nav(),
        session,
    )


@app.get("/mail/settings/forwarding", response_class=HTMLResponse)
def forwarding_settings(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    try:
        rule = get_forwarding_rule(conn, session["user_id"])
    finally:
        conn.close()
    csrf = html.escape(session["csrf"])
    body = (
        "<h1>Forwarding settings</h1>" + mail_nav()
        + "<div class='card'><p><b>Current rule:</b> "
        + (html.escape(rule) if rule else "<span class='muted'>(none)</span>")
        + "</p>"
        "<form method='post' action='/mail/forward'>"
        "<input type='hidden' name='csrf_token' value='" + csrf + "'>"
        "<label for='target'>Forward all incoming mail to</label>"
        "<input id='target' name='target' placeholder='attacker@datn.local'"
        + (" value='" + html.escape(rule) + "'" if rule else "") + ">"
        "<button class='primary' type='submit'>Save forwarding rule</button>"
        "</form></div>"
    )
    return page("Forwarding", body, session)


@app.post("/mail/forward", response_class=HTMLResponse)
async def set_forwarding(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await form_data(request)
    if not check_csrf(request, session, form):
        return page("Forbidden", "<h1>Forbidden</h1><p>Bad CSRF token.</p>",
                    session, status_code=403)
    target = normalize_email(form.get("target", ""))
    if not target:
        return page("Forwarding", "<h1>Forwarding</h1><p class='error'>"
                    "Target address is required.</p>", session, status_code=400)
    conn = db()
    try:
        conn.execute(
            "INSERT INTO forwarding_rules(user_id, target_address, created_at) "
            "VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
            "target_address=excluded.target_address, "
            "created_at=excluded.created_at",
            (session["user_id"], target, now_ts()),
        )
        conn.commit()
    finally:
        conn.close()
    log_event(
        request, "mailbox_rule_created", "mail", "warning", "success",
        user_id=session["user_id"], jti=session["jti"],
        extra={"mailbox": session["user_id"], "rule": target},
    )
    return RedirectResponse("/mail/settings/forwarding", status_code=303)


@app.post("/api/token")
async def issue_token(request: Request):
    session = get_session(request)
    if not session:
        log_event(
            request, "token_issued", "token", "warning", "denied",
            extra={"reason": "no_session"},
        )
        return JSONResponse({"detail": "authentication required"}, status_code=401)
    conn = db()
    try:
        user = get_user(conn, session["user_id"])
    finally:
        conn.close()
    if not user:
        return JSONResponse({"detail": "unknown user"}, status_code=401)
    now = int(time.time())
    expires_at = now + TOKEN_TTL
    jti = "jwt-" + uuid.uuid4().hex
    payload = {
        "sub": session["user_id"],
        "jti": jti,
        "role": user["role"],
        "iat": now,
        "exp": expires_at,
        "iss": JWT_ISS,
        "aud": JWT_AUD,
    }
    token = jwt_encode(payload)
    conn = db()
    try:
        conn.execute(
            "INSERT INTO tokens(jti, user_id, role, token, issued_at, "
            "expires_at, issued_src) VALUES(?,?,?,?,?,?,?)",
            (jti, session["user_id"], user["role"], token, now, expires_at,
             client_ip(request)),
        )
        conn.commit()
    finally:
        conn.close()
    log_event(
        request, "token_issued", "token", "info", "success",
        user_id=session["user_id"], jti=jti,
        extra={"expires_at": expires_at, "token_type": "bearer"},
    )
    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "jti": jti,
    })


def _audit_bearer(request, path):
    payload, reason = authenticate_bearer(request)
    if reason or payload is None:
        log_event(
            request, "token_rejected", "api", "warning", "failure",
            user_id=(payload or {}).get("sub"),
            jti=(payload or {}).get("jti"),
            extra={"reason": reason, "path": path},
        )
        return None, None, reason
    user_id = payload.get("sub")
    jti = payload.get("jti")
    conn = db()
    try:
        user = get_user(conn, user_id) if user_id else None
        token_row = conn.execute(
            "SELECT issued_src FROM tokens WHERE jti=?", (jti,)
        ).fetchone()
    finally:
        conn.close()
    if not user:
        log_event(
            request, "token_rejected", "api", "warning", "failure",
            user_id=user_id, jti=jti,
            extra={"reason": "unknown_user", "path": path},
        )
        return None, None, "unknown_user"
    log_event(
        request, "api_access", "api", "info", "success",
        user_id=user_id, jti=jti,
        extra={"path": path, "method": "GET",
               "token_src": token_row["issued_src"] if token_row else None,
               "replay": bool(token_row and token_row["issued_src"]
                              and token_row["issued_src"] != client_ip(request))},
    )
    return payload, user, None


@app.get("/api/me")
def api_me(request: Request):
    payload, user, reason = _audit_bearer(request, "/api/me")
    if reason or user is None:
        return JSONResponse({"detail": "invalid_token", "reason": reason},
                            status_code=401)
    return JSONResponse({
        "sub": user["email"],
        "role": user["role"],
        "phone": user["phone"],
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "jti": payload.get("jti"),
    })


@app.get("/api/mailbox/summary")
def api_mailbox_summary(request: Request):
    payload, user, reason = _audit_bearer(request, "/api/mailbox/summary")
    if reason or user is None:
        return JSONResponse({"detail": "invalid_token", "reason": reason},
                            status_code=401)
    conn = db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM mails WHERE owner=?", (user["email"],)
        ).fetchone()["c"]
        last = conn.execute(
            "SELECT subject FROM mails WHERE owner=? ORDER BY id DESC LIMIT 1",
            (user["email"],),
        ).fetchone()
        rule = get_forwarding_rule(conn, user["email"])
    finally:
        conn.close()
    return JSONResponse({
        "sub": user["email"],
        "total_messages": total,
        "last_subject": last["subject"] if last else None,
        "forwarding_rule": rule,
        "jti": payload.get("jti"),
    })


@app.get("/debug/sessions")
def debug_sessions(request: Request):
    now = time.time()
    conn = db()
    try:
        web_rows = conn.execute("SELECT * FROM sessions").fetchall()
        jwt_rows = conn.execute(
            "SELECT * FROM tokens WHERE revoked=0"
        ).fetchall()
    finally:
        conn.close()
    out = []
    for row in web_rows:
        if float(row["created_at"]) + SESSION_TTL < now:
            continue
        out.append({
            "type": "web",
            "session_id": row["sid"],
            "jti": row["jti"],
            "user_id": row["user_id"],
            "created_at": row["created_at"],
            "last_seen": row["last_seen"],
            "src_ip": row["src_ip"],
            "user_agent": row["user_agent"],
        })
    for row in jwt_rows:
        if float(row["expires_at"]) < now:
            continue
        out.append({
            "type": "jwt",
            "jti": row["jti"],
            "user_id": row["user_id"],
            "role": row["role"],
            "token": row["token"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "issued_src": row["issued_src"],
        })
    log_event(
        request, "debug_sessions_viewed", "audit", "high", "success",
        extra={"active_sessions": len(web_rows), "active_tokens": len(jwt_rows)},
    )
    return JSONResponse({
        "service": SERVICE,
        "generated_at": utc_iso(),
        "counts": {"sessions": len(web_rows), "tokens": len(jwt_rows)},
        "sessions": out,
    })


@app.get("/debug/forwarding")
def debug_forwarding(request: Request):
    """Forgotten diagnostic endpoint: live forwarding-rule inventory.

    The SOC correlation script uses this to diff the current rules against
    the approved baseline. Like /debug/sessions, it should not exist in
    production.
    """
    conn = db()
    try:
        rows = conn.execute(
            "SELECT user_id, target_address, created_at FROM forwarding_rules "
            "ORDER BY user_id"
        ).fetchall()
    finally:
        conn.close()
    rules = [{
        "user_id": row["user_id"],
        "target_address": row["target_address"],
        "created_at": row["created_at"],
    } for row in rows]
    log_event(
        request, "debug_forwarding_viewed", "audit", "high", "success",
        extra={"rules": len(rules)},
    )
    return JSONResponse({
        "service": SERVICE,
        "generated_at": utc_iso(),
        "rules": rules,
    })


@app.get("/debug/audit")
def debug_audit(request: Request):
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        content = ""
    log_event(
        request, "debug_audit_exported", "audit", "high", "success",
        extra={"bytes": len(content.encode("utf-8")), "file": LOG_PATH},
    )
    return PlainTextResponse(content, media_type="application/x-ndjson")


@app.get("/backup/users.csv")
def leaked_backup(request: Request):
    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return PlainTextResponse("not found\n", status_code=404,
                                 media_type="text/plain")
    records = max(0, len([
        line for line in content.splitlines()
        if line.strip() and not line.startswith("#")
    ]) - 1)
    log_event(
        request, "backup_downloaded", "credential", "high", "success",
        extra={"file": "backup/users.csv", "records": records},
    )
    return PlainTextResponse(content, media_type="text/csv")


@app.post("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    session = get_session(request)
    if session:
        form = await form_data(request)
        if not check_csrf(request, session, form):
            return page("Forbidden", "<h1>Forbidden</h1><p>Bad CSRF token.</p>",
                        session, status_code=403)
        conn = db()
        try:
            conn.execute("DELETE FROM sessions WHERE sid=?", (session["sid"],))
            conn.commit()
        finally:
            conn.close()
        log_event(
            request, "logout", "auth", "info", "success",
            user_id=session["user_id"], jti=session["jti"],
        )
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response


@app.get("/health")
def health():
    return JSONResponse({"status": "ok", "service": SERVICE})


ensure_log_dir()
init_db()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
