#!/usr/bin/env python3
"""detect.py -- SOC forwarding-rule detector (teaching version).

Workflow:
  fetch_logs.sh            # scp mail.log + mail.db from victim-mail
  python3 detect.py --diff # list current rules vs approved inventory,
                           # spot the unapproved one(s) and triage them
  # ... fix rules.json (see --help) ...
  python3 detect.py --detect # write alerts.log + SUMMARY (graded)

Usage: detect.py [--db PATH] [--rules PATH] [--known PATH] [--out PATH]
                 [--diff | --detect | --help]
Defaults assume fetch_logs.sh already ran (/home/ubuntu/collected/mail.db).
"""
import json
import os
import sqlite3
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = "/home/ubuntu/collected/mail.db"
RULES_PATH = os.path.join(APP_DIR, "rules.json")
KNOWN_PATH = os.path.join(APP_DIR, "known_forwarding.json")
OUT_PATH = os.environ.get("SOC_ALERTS", "/var/log/soc/alerts.log")


def usage():
    print(__doc__)
    print("rules.json modes:")
    print('  {"mode": "exact_ioc", "iocs": ["bad.example", ...]}')
    print('     alert iff an IOC string appears in the target address.')
    print('     (starter pack: stale threat intel -- misses lookalikes)')
    print('  {"mode": "allowlist"}')
    print('     alert iff the target domain is NOT in the approved')
    print('     inventory (domains derived automatically).')


def domain_of(addr):
    return addr.split("@")[-1].strip().lower() if "@" in addr else ""


def load_rules(path):
    with open(path) as f:
        return json.load(f)


def load_known(path):
    with open(path) as f:
        return set(json.load(f))


def load_current(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT DISTINCT user, target_address FROM forwarding_rules"
    ).fetchall()
    conn.close()
    return [(r["user"], r["target_address"]) for r in rows]


def match(target, rules, known):
    mode = rules.get("mode", "exact_ioc")
    if mode == "allowlist":
        allowed = {domain_of(a) for a in known}
        return domain_of(target) not in allowed
    for ioc in rules.get("iocs", []):
        if ioc and ioc in target:
            return True
    return False


def main(argv):
    if "--help" in argv or "-h" in argv or len(argv) < 2:
        usage()
        return 0
    db_path, rules_path, known_path, out_path = DB_PATH, RULES_PATH, KNOWN_PATH, OUT_PATH
    for a in argv[1:]:
        if a.startswith("--db="):
            db_path = a.split("=", 1)[1]
        elif a.startswith("--rules="):
            rules_path = a.split("=", 1)[1]
        elif a.startswith("--known="):
            known_path = a.split("=", 1)[1]
        elif a.startswith("--out="):
            out_path = a.split("=", 1)[1]
    if not os.path.exists(db_path):
        print("mail.db not found at %s -- run fetch_logs.sh first" % db_path)
        return 1
    known = load_known(known_path)
    rules = load_rules(rules_path)
    current = load_current(db_path)
    unapproved = [(u, t) for (u, t) in current if t not in known]
    if "--diff" in argv:
        print("INVENTORY total=%d approved=%d" % (len(current), len(current) - len(unapproved)))
        print("UNAPPROVED=%d" % len(unapproved))
        for u, t in sorted(unapproved):
            print("UNAPPROVED %s->%s" % (u, t))
        if not unapproved:
            print("(none -- every rule is approved)")
        return 0
    if "--detect" in argv:
        lines = []
        lines.append("CONFIG mode=%s" % rules.get("mode", "exact_ioc"))
        lines.append("INVENTORY total=%d approved=%d UNAPPROVED=%d"
                     % (len(current), len(current) - len(unapproved),
                        len(unapproved)))
        for u, t in sorted(unapproved):
            lines.append("UNAPPROVED %s->%s" % (u, t))
        tp = fp = 0
        for u, t in sorted(current):
            if match(t, rules, known):
                lines.append("ALERT forward %s->%s" % (u, t))
                if t not in known:
                    tp += 1
                else:
                    fp += 1
        lines.append("SUMMARY tp=%d fp=%d" % (tp, fp))
        with open(out_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("\n".join(lines))
        return 0
    usage()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
