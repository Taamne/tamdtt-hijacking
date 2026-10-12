#!/usr/bin/env python3
"""Legacy plaintext mail-check service (TCP 2323) for the Email Hijacking lab.

Simulates an old unencrypted remote-mail protocol: the client sends the
username and password as plain text lines. Anyone sniffing the wire
(e.g. with tcpdump) recovers the mailbox credential. Prompts end with
a newline so simple scripted clients work reliably.
"""
import logging
import os
import socket
import sqlite3
import threading

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "mail.db")
LOG_PATH = os.environ.get("VICTIM_MAIL_LOG", "/var/log/victim-mail/mail.log")
PORT = 2323

handler = logging.FileHandler(LOG_PATH)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
event_log = logging.getLogger("victim-mail-legacy")
event_log.setLevel(logging.INFO)
event_log.addHandler(handler)
event_log.propagate = False


def check_cred(username, password):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return row is not None and row["password"] == password


def inbox_count(username):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    n = conn.execute(
        "SELECT COUNT(*) AS c FROM mails WHERE owner=?", (username,)
    ).fetchone()["c"]
    conn.close()
    return n


def handle(conn, addr):
    src = addr[0]
    try:
        f = conn.makefile("rw", newline="\n")
        f.write("Legacy Mail Check v1.0 (plaintext, do not use on untrusted nets)\n")
        f.write("login:\n")
        f.flush()
        username = (f.readline() or "").strip()
        f.write("Password:\n")
        f.flush()
        password = (f.readline() or "").strip()
        if username and check_cred(username, password):
            event_log.info("LEGACY_AUTH user=%s src=%s result=ok", username, src)
            f.write("OK. INBOX: %d messages.\n" % inbox_count(username))
        else:
            event_log.info(
                "LEGACY_AUTH user=%s src=%s result=fail", username, src)
            f.write("ERR. Invalid credentials.\n")
        f.flush()
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as exc:  # never let one bad client kill the thread pool
        try:
            event_log.info("LEGACY_ERROR src=%s err=%s", src, exc)
        except OSError:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(20)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
