#!/usr/bin/env python3
"""DATN Portal - audit log correlation / incident detection demo.

Pulls the JSONL audit log from the portal's forgotten /debug/audit endpoint
(or reads a local copy), builds a timeline, and correlates three signals
into one incident per user:

  account_hijack   login_success from an IP other than the clean baseline
  mailbox_hijack   forwarding rule created / mail forwarded / mail read
                   from the attacker source
  token_hijack     a JWT issued from one IP is used from another IP

Supporting signals:
  session_not_revoked  password changed in baseline mode, old token still used
  recon                 /debug/sessions or /debug/audit fetched off-baseline

Outputs:
  <out-dir>/timeline.csv
  <out-dir>/incident_summary.json

Usage:
  python3 detector/detect.py
  python3 detector/detect.py --log-file /tmp/app.jsonl
  python3 detector/detect.py --expected-ip 172.26.0.4 --out-dir ~/incident
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "http://victim-portal:8000/debug/audit"
DEFAULT_OUT_DIR = "/home/ubuntu/incident"
DEFAULT_EXPECTED_IP = "172.26.0.4"

PRIMARY_SIGNALS = ("account_hijack", "mailbox_hijack", "token_hijack")


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_text(url, log_file):
    if log_file:
        with open(log_file, "r", encoding="utf-8") as fh:
            return fh.read(), log_file
    with urllib.request.urlopen(url, timeout=15) as response:
        return response.read().decode("utf-8"), url


def parse_events(text):
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("event_type"):
            events.append(event)
    events.sort(key=lambda item: item.get("timestamp") or "")
    return events


def event_ts(event):
    return event.get("timestamp") or ""


def add_signal(incidents, user, signal_type, event):
    user = user or "-"
    incident = incidents.setdefault(user, {
        "signals": {},
        "event_ids": [],
        "jti": set(),
        "src_ips": set(),
    })
    signal = incident["signals"].setdefault(signal_type, {
        "count": 0,
        "event_ids": [],
        "first_seen": None,
        "last_seen": None,
        "src_ips": set(),
    })
    signal["count"] += 1
    event_id = event.get("event_id")
    if event_id:
        signal["event_ids"].append(event_id)
        incident["event_ids"].append(event_id)
    timestamp = event_ts(event)
    if timestamp:
        if signal["first_seen"] is None or timestamp < signal["first_seen"]:
            signal["first_seen"] = timestamp
        if signal["last_seen"] is None or timestamp > signal["last_seen"]:
            signal["last_seen"] = timestamp
    src_ip = event.get("src_ip")
    if src_ip:
        signal["src_ips"].add(src_ip)
        incident["src_ips"].add(src_ip)
    jti = event.get("jti")
    if jti:
        incident["jti"].add(jti)


def build_timeline(events, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "timestamp", "event_type", "severity", "result", "user_id",
            "src_ip", "jti", "mailbox", "rule", "event_id", "request_id",
        ])
        for event in events:
            writer.writerow([
                event.get("timestamp", ""),
                event.get("event_type", ""),
                event.get("severity", ""),
                event.get("result", ""),
                event.get("user_id", ""),
                event.get("src_ip", ""),
                event.get("jti", ""),
                event.get("mailbox", ""),
                event.get("rule", ""),
                event.get("event_id", ""),
                event.get("request_id", ""),
            ])


def detect(events, expected_ip):
    token_src = {}
    token_ts = {}
    baseline_users = set()

    for event in events:
        event_type = event.get("event_type")
        if event_type == "login_success" and event.get("src_ip") == expected_ip:
            baseline_users.add(event.get("user_id"))
        if event_type == "token_issued":
            token_src[event.get("jti")] = event.get("src_ip")
            token_ts[event.get("jti")] = event_ts(event)

    incidents = {}
    recon = []
    password_events = []

    for event in events:
        event_type = event.get("event_type")
        user = event.get("user_id")
        src_ip = event.get("src_ip")

        if (event_type == "login_success" and user in baseline_users
                and src_ip and src_ip != expected_ip):
            add_signal(incidents, user, "account_hijack", event)

        if event_type in ("mailbox_rule_created", "mail_forwarded"):
            add_signal(incidents, user, "mailbox_hijack", event)

        if (event_type == "mail_read" and user in baseline_users
                and src_ip and src_ip != expected_ip):
            add_signal(incidents, user, "mailbox_hijack", event)

        if event_type == "api_access":
            jti = event.get("jti")
            if jti in token_src and src_ip and src_ip != token_src[jti]:
                add_signal(incidents, user, "token_hijack", event)

        if (event_type in ("debug_sessions_viewed", "debug_audit_exported")
                and src_ip and src_ip != expected_ip):
            recon.append(event)

        if event_type == "password_changed" and event.get("result") == "success":
            password_events.append(event)

    # A baseline (non-hardened) password change is only interesting if an
    # older token still works afterwards.
    for password_event in password_events:
        if password_event.get("hardened"):
            continue
        user = password_event.get("user_id")
        changed_at = event_ts(password_event)
        old_jtis = {
            jti for jti, issued_at in token_ts.items()
            if issued_at and issued_at <= changed_at
        }
        for event in events:
            if (event.get("event_type") == "api_access"
                    and event.get("user_id") == user
                    and event_ts(event) > changed_at
                    and event.get("jti") in old_jtis):
                add_signal(incidents, user, "session_not_revoked", password_event)
                break

    recon_ids = [e.get("event_id") for e in recon if e.get("event_id")]
    recon_summary = [{
        "timestamp": e.get("timestamp"),
        "event_type": e.get("event_type"),
        "src_ip": e.get("src_ip"),
        "event_id": e.get("event_id"),
    } for e in recon]

    results = []
    for user, incident in incidents.items():
        signals = incident["signals"]
        primary = [name for name in PRIMARY_SIGNALS if name in signals]
        supporting = [name for name in ("session_not_revoked",) if name in signals]
        if len(primary) >= 3:
            severity = "critical"
        elif len(primary) == 2:
            severity = "high"
        elif len(primary) == 1:
            severity = "medium"
        else:
            severity = "low"
        all_times = [
            value for name in signals
            for value in (signals[name]["first_seen"], signals[name]["last_seen"])
            if value
        ]
        first_seen = min(all_times) if all_times else None
        last_seen = max(all_times) if all_times else None
        signal_out = []
        for name in sorted(signals):
            item = signals[name]
            signal_out.append({
                "type": name,
                "count": item["count"],
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "src_ips": sorted(item["src_ips"]),
                "event_ids": item["event_ids"],
            })
        digest = hashlib.sha1(
            ((user or "") + (first_seen or "")).encode("utf-8")
        ).hexdigest()[:8]
        results.append({
            "incident_id": "INC-" + digest,
            "user_id": user,
            "severity": severity,
            "primary_signals": primary,
            "supporting_signals": supporting,
            "signals": signal_out,
            "src_ips": sorted(incident["src_ips"]),
            "jti": sorted(incident["jti"]),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_ids": incident["event_ids"],
            "supporting_event_ids": recon_ids,
            "supporting_events": recon_summary,
            "summary": (
                "user %s: %s%s" % (
                    user,
                    ", ".join(primary) if primary else "supporting only",
                    " (" + ", ".join(supporting) + ")" if supporting else "",
                )
            ),
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda item: (order.get(item["severity"], 9), item["user_id"]))
    return results, recon_summary


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Correlate the DATN Portal JSONL audit log into incidents."
    )
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="portal audit endpoint (default: %s)" % DEFAULT_URL)
    parser.add_argument("--log-file", default=None,
                        help="read a local JSONL file instead of the endpoint")
    parser.add_argument("--expected-ip", default=DEFAULT_EXPECTED_IP,
                        help="clean baseline source IP (default: %s)"
                             % DEFAULT_EXPECTED_IP)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="output directory (default: %s)" % DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)

    try:
        text, source = load_text(args.url, args.log_file)
    except Exception as exc:
        print("ERROR: could not read audit log: %s" % exc, file=sys.stderr)
        return 1

    events = parse_events(text)
    if not events:
        print("WARNING: no parseable audit events found (source: %s)" % source,
              file=sys.stderr)

    os.makedirs(args.out_dir, exist_ok=True)
    timeline_path = os.path.join(args.out_dir, "timeline.csv")
    summary_path = os.path.join(args.out_dir, "incident_summary.json")

    build_timeline(events, timeline_path)
    incidents, recon = detect(events, args.expected_ip)

    summary = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "log_source": source,
        "expected_baseline_ip": args.expected_ip,
        "counts": {
            "events": len(events),
            "incidents": len(incidents),
            "recon_events": len(recon),
        },
        "recon_events": recon,
        "incidents": incidents,
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    print("events=%d incidents=%d recon=%d" % (
        len(events), len(incidents), len(recon)))
    for incident in incidents:
        print("[%s] %s  signals=%s" % (
            incident["severity"].upper(),
            incident["user_id"],
            ",".join(incident["primary_signals"]) or "supporting-only",
        ))
        if incident["supporting_signals"]:
            print("         supporting=%s" % ",".join(incident["supporting_signals"]))
        print("         src_ips=%s" % ",".join(incident["src_ips"]))
    if not incidents:
        print("No correlated incident found. Run the attack steps first.")
    print("timeline: %s" % timeline_path)
    print("summary : %s" % summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
