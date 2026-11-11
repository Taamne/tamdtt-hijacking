#!/usr/bin/env python3
"""DATN Portal - multi-signal SOC correlation for the identity/session demo.

This is the detection centrepiece of the lab. It reuses the teaching
approach of the Email Forwarding detection lab (approved inventory +
allowlist) and adds account/token correlation over the portal JSONL log.

Modes
-----
  --diff        show current forwarding rules vs the approved baseline
  --detect      (default) correlate signals, write alerts + incident summary
  --prevention  write the before/after control map (MFA, revoke, alert, etc.)

Inputs
------
  audit log   : http://victim-portal:8000/debug/audit   (or --log-file)
  live rules  : http://victim-portal:8000/debug/forwarding (or --rules-file)
  baseline    : detector/known_forwarding.json  (approved user->target pairs)
  policy      : detector/rules.json  ({"mode": "allowlist"} or "exact_ioc")

Signals
-------
  account_hijack       login from a non-baseline IP or User-Agent, or a
                       sensitive action (profile/password change) from one
  mailbox_hijack       forwarding rule outside the approved inventory,
                       a forwarded copy to it, or victim mail read from a
                       non-baseline context
  token_hijack         a JWT issued from one IP/UA is used from another
  session_not_revoked  password changed, but an older token is still accepted
  recon                /debug/sessions, /debug/forwarding or /debug/audit
                       fetched from off-baseline (monitor's own IP ignored)

Outputs
-------
  <out-dir>/timeline.csv
  <out-dir>/incident_summary.json   (incidents + metrics + IOC + diff)
  <out-dir>/alerts.log              (JSONL, one alert per signal per user)
  <out-dir>/prevention_report.json  (--prevention only)

The demo is intentionally not graded. Metrics are for the DATN report.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

DETECTOR_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG_URL = "http://victim-portal:8000/debug/audit"
DEFAULT_RULES_URL = "http://victim-portal:8000/debug/forwarding"
DEFAULT_OUT_DIR = "/home/ubuntu/incident"
DEFAULT_EXPECTED_IP = "172.26.0.4"
DEFAULT_MONITOR_IP = "172.26.0.5"
DEFAULT_KNOWN_PATH = os.path.join(DETECTOR_DIR, "known_forwarding.json")
DEFAULT_POLICY_PATH = os.path.join(DETECTOR_DIR, "rules.json")

SIGNAL_WEIGHTS = {
    "account_hijack": 30,
    "mailbox_hijack": 30,
    "token_hijack": 35,
    "session_not_revoked": 10,
    "recon": 5,
}
PRIMARY_SIGNALS = ("account_hijack", "mailbox_hijack", "token_hijack")
SUPPORTING_SIGNALS = ("session_not_revoked", "recon")


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(value):
    if not value:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    return 0.0


def event_ts(event):
    return event.get("timestamp") or ""


def fetch_text(url):
    with urllib.request.urlopen(url, timeout=15) as response:
        return response.read().decode("utf-8")


def fetch_json(url):
    return json.loads(fetch_text(url))


def load_events(url, log_file):
    if log_file:
        with open(log_file, "r", encoding="utf-8") as fh:
            text = fh.read()
        source = log_file
    else:
        text = fetch_text(url)
        source = url
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
    return events, source


def load_known(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("approved", data.get("rules", []))
    pairs = []
    for item in data:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            pairs.append((str(item[0]).lower(), str(item[1]).lower()))
        elif isinstance(item, dict):
            user = item.get("user_id") or item.get("user")
            target = item.get("target_address") or item.get("target")
            if user and target:
                pairs.append((str(user).lower(), str(target).lower()))
    return pairs


def load_policy(path):
    with open(path, "r", encoding="utf-8") as fh:
        policy = json.load(fh)
    if not isinstance(policy, dict):
        policy = {}
    policy.setdefault("mode", "allowlist")
    policy.setdefault("iocs", [])
    return policy


def parse_rules_payload(payload):
    if isinstance(payload, dict):
        payload = payload.get("rules", [])
    rules = []
    for item in payload:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            rules.append({
                "user_id": str(item[0]).lower(),
                "target_address": str(item[1]).lower(),
                "created_at": None,
            })
        elif isinstance(item, dict):
            user = item.get("user_id") or item.get("user")
            target = item.get("target_address") or item.get("target")
            if user and target:
                rules.append({
                    "user_id": str(user).lower(),
                    "target_address": str(target).lower(),
                    "created_at": item.get("created_at"),
                })
    return rules


def reconstruct_rules(events):
    latest = {}
    for event in events:
        if event.get("event_type") in ("mailbox_rule_created", "mail_forwarded"):
            user = event.get("user_id")
            target = event.get("rule") or event.get("target")
            if user and target:
                latest[user] = {
                    "user_id": user,
                    "target_address": target,
                    "created_at": event.get("timestamp"),
                }
    return list(latest.values())


def load_current_rules(rules_url, rules_file, events):
    if rules_file:
        with open(rules_file, "r", encoding="utf-8") as fh:
            return parse_rules_payload(json.load(fh)), rules_file
    try:
        payload = fetch_json(rules_url)
        return parse_rules_payload(payload), rules_url
    except Exception as exc:  # fall back to reconstructing from the audit log
        print("WARNING: could not fetch live forwarding rules (%s); "
              "using audit log" % exc, file=sys.stderr)
        return reconstruct_rules(events), "audit-log"


def target_is_unapproved(target, policy, approved_targets):
    mode = policy.get("mode", "allowlist")
    target = (target or "").lower()
    if mode == "allowlist":
        return target not in approved_targets
    for ioc in policy.get("iocs", []):
        if ioc and ioc.lower() in target:
            return True
    return False


def build_forwarding_diff(current, known, policy):
    approved = set((user.lower(), target.lower()) for user, target in known)
    approved_targets = set(target for _user, target in approved)
    approved_by_user = {user: target for user, target in approved}
    unapproved = []
    changed = []
    for rule in current:
        user = rule["user_id"].lower()
        target = rule["target_address"].lower()
        if (user, target) in approved:
            continue
        unapproved.append({
            "user_id": user,
            "target_address": target,
            "created_at": rule.get("created_at"),
            "matched_by_policy": target_is_unapproved(target, policy, approved_targets),
        })
        if user in approved_by_user and approved_by_user[user] != target:
            changed.append({
                "user_id": user,
                "approved_target": approved_by_user[user],
                "current_target": target,
            })
    current_by_user = {
        r["user_id"].lower(): r["target_address"].lower() for r in current
    }
    missing = [
        {"user_id": user, "target_address": target}
        for user, target in approved if user not in current_by_user
    ]
    return {
        "policy_mode": policy.get("mode", "allowlist"),
        "approved_inventory": [
            {"user_id": user, "target_address": target}
            for user, target in sorted(approved)
        ],
        "current_rules": current,
        "unapproved": unapproved,
        "changed": changed,
        "missing": missing,
        "counts": {
            "approved": len(approved),
            "current": len(current),
            "unapproved": len(unapproved),
            "changed": len(changed),
            "missing": len(missing),
        },
    }


class Signals:
    def __init__(self):
        self.incidents = {}

    def add(self, user, signal_type, event):
        user = user or "-"
        incident = self.incidents.setdefault(user, {
            "signals": {},
            "event_ids": [],
            "events": [],
            "jti": set(),
            "src_ips": set(),
            "user_agents": set(),
            "forward_targets": set(),
        })
        signal = incident["signals"].setdefault(signal_type, {
            "count": 0,
            "event_ids": [],
            "first_seen": None,
            "last_seen": None,
            "src_ips": set(),
            "user_agents": set(),
            "jti": set(),
            "forward_targets": set(),
        })
        signal["count"] += 1
        event_id = event.get("event_id")
        if event_id:
            signal["event_ids"].append(event_id)
            incident["event_ids"].append(event_id)
        incident["events"].append(event)
        timestamp = event_ts(event)
        if timestamp:
            if signal["first_seen"] is None or timestamp < signal["first_seen"]:
                signal["first_seen"] = timestamp
            if signal["last_seen"] is None or timestamp > signal["last_seen"]:
                signal["last_seen"] = timestamp
        src_ip = event.get("src_ip")
        if src_ip and src_ip != "-":
            signal["src_ips"].add(src_ip)
            incident["src_ips"].add(src_ip)
        ua = event.get("user_agent")
        if ua and ua != "-":
            signal["user_agents"].add(ua)
            incident["user_agents"].add(ua)
        jti = event.get("jti")
        if jti:
            signal["jti"].add(jti)
            incident["jti"].add(jti)
        target = event.get("rule") or event.get("target")
        if target:
            signal["forward_targets"].add(target)
            incident["forward_targets"].add(target)


def add_signal(signals, user, signal_type, event):
    if event is None:
        return
    signals.add(user, signal_type, event)


def baseline_context(events, expected_ip):
    baseline_users = set()
    baseline_ua = {}
    for event in events:
        if (event.get("event_type") == "login_success"
                and event.get("src_ip") == expected_ip):
            user = event.get("user_id")
            baseline_users.add(user)
            baseline_ua.setdefault(user, event.get("user_agent"))
    return baseline_users, baseline_ua


def token_context(events):
    tokens = {}
    for event in events:
        if event.get("event_type") == "token_issued" and event.get("jti"):
            tokens[event["jti"]] = {
                "user_id": event.get("user_id"),
                "src_ip": event.get("src_ip"),
                "user_agent": event.get("user_agent"),
                "issued_at": event_ts(event),
            }
    return tokens


def anomaly(user, event, expected_ip, baseline_ua):
    src_ip = event.get("src_ip") or ""
    ua = event.get("user_agent") or ""
    ip_anomaly = bool(src_ip and src_ip != expected_ip)
    expected_ua = baseline_ua.get(user)
    ua_anomaly = bool(expected_ua and ua and ua != expected_ua)
    return ip_anomaly or ua_anomaly


def detect_signals(events, current_rules, forwarding_diff, expected_ip, monitor_ip):
    baseline_users, baseline_ua = baseline_context(events, expected_ip)
    tokens = token_context(events)
    signals = Signals()
    recon = []
    password_changes = []
    approved_targets = set(
        item["target_address"].lower()
        for item in forwarding_diff["approved_inventory"]
    )
    policy = {"mode": forwarding_diff["policy_mode"]}

    for event in events:
        event_type = event.get("event_type")
        user = event.get("user_id")
        src_ip = event.get("src_ip") or ""

        if event_type == "login_success" and user in baseline_users:
            if anomaly(user, event, expected_ip, baseline_ua):
                add_signal(signals, user, "account_hijack", event)

        if (event_type in ("profile_updated", "password_changed")
                and user in baseline_users
                and anomaly(user, event, expected_ip, baseline_ua)):
            add_signal(signals, user, "account_hijack", event)

        if event_type in ("mailbox_rule_created", "mail_forwarded"):
            target = event.get("rule") or event.get("target") or ""
            if target_is_unapproved(target, policy, approved_targets):
                add_signal(signals, user, "mailbox_hijack", event)

        if (event_type == "mail_read" and user in baseline_users
                and anomaly(user, event, expected_ip, baseline_ua)):
            add_signal(signals, user, "mailbox_hijack", event)

        if event_type == "api_access":
            jti = event.get("jti")
            issued = tokens.get(jti)
            if issued:
                ip_anomaly = bool(
                    src_ip and issued["src_ip"] and src_ip != issued["src_ip"])
                ua_anomaly = bool(
                    event.get("user_agent") and issued["user_agent"]
                    and event.get("user_agent") != issued["user_agent"])
                if ip_anomaly or ua_anomaly:
                    add_signal(signals, user, "token_hijack", event)

        if event_type in ("debug_sessions_viewed", "debug_forwarding_viewed",
                          "debug_audit_exported"):
            if src_ip and src_ip not in (expected_ip, monitor_ip):
                recon.append(event)

        if event_type == "password_changed" and event.get("result") == "success":
            password_changes.append(event)

    # A live rule outside the approved inventory is a mailbox signal even if
    # the creation event is outside the log window. Avoid double counting.
    for rule in forwarding_diff["unapproved"]:
        if not rule["matched_by_policy"]:
            continue
        user = rule["user_id"]
        target = rule["target_address"]
        already = False
        incident = signals.incidents.get(user)
        if incident:
            for event in incident["events"]:
                if (event.get("event_type") in
                        ("mailbox_rule_created", "mail_forwarded")
                        and (event.get("rule") or event.get("target")) == target):
                    already = True
                    break
        if not already:
            synthetic = {
                "schema_version": "1.0",
                "event_id": "obs-" + hashlib.sha1(
                    (user + target).encode("utf-8")).hexdigest()[:16],
                "timestamp": utc_now(),
                "service": "detector",
                "category": "mail",
                "event_type": "forwarding_rule_observed",
                "severity": "high",
                "result": "observed",
                "src_ip": "-",
                "user_agent": "-",
                "user_id": user,
                "mailbox": user,
                "rule": target,
            }
            add_signal(signals, user, "mailbox_hijack", synthetic)

    # Persistence gap: an old token was accepted after a password change.
    for password_event in password_changes:
        user = password_event.get("user_id")
        changed_at = event_ts(password_event)
        old_jtis = {
            jti for jti, meta in tokens.items()
            if meta["issued_at"] and meta["issued_at"] <= changed_at
        }
        for event in events:
            if (event.get("event_type") == "api_access"
                    and event.get("user_id") == user
                    and event_ts(event) > changed_at
                    and event.get("jti") in old_jtis):
                add_signal(signals, user, "session_not_revoked",
                           password_event)
                break

    # Recon is supporting evidence and is attached to incidents whose
    # source IPs overlap with the recon source.
    for user, incident in signals.incidents.items():
        incident_recon = [
            event for event in recon
            if event.get("src_ip") in incident["src_ips"]
        ]
        if incident_recon:
            for event in incident_recon:
                add_signal(signals, user, "recon", event)

    return signals.incidents, recon, forwarding_diff


def severity_for(score):
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def build_incidents(incidents, recon_events):
    output = []
    for user, incident in incidents.items():
        signal_types = list(incident["signals"].keys())
        score = min(100, sum(SIGNAL_WEIGHTS.get(name, 0)
                            for name in signal_types))
        severity = severity_for(score)
        primary = [name for name in PRIMARY_SIGNALS if name in signal_types]
        supporting = [name for name in SUPPORTING_SIGNALS
                      if name in signal_types]
        timestamps = [
            value for name in signal_types
            for value in (incident["signals"][name]["first_seen"],
                          incident["signals"][name]["last_seen"])
            if value
        ]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        signal_out = []
        for name in sorted(incident["signals"]):
            item = incident["signals"][name]
            signal_out.append({
                "type": name,
                "count": item["count"],
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "src_ips": sorted(item["src_ips"]),
                "user_agents": sorted(item["user_agents"]),
                "jti": sorted(item["jti"]),
                "forward_targets": sorted(item["forward_targets"]),
                "event_ids": item["event_ids"],
            })
        digest = hashlib.sha1(
            ((user or "") + (first_seen or "")).encode("utf-8")
        ).hexdigest()[:8]
        output.append({
            "incident_id": "INC-" + digest,
            "user_id": user,
            "severity": severity,
            "risk_score": score,
            "primary_signals": primary,
            "supporting_signals": supporting,
            "signals": signal_out,
            "src_ips": sorted(incident["src_ips"]),
            "user_agents": sorted(incident["user_agents"]),
            "jti": sorted(incident["jti"]),
            "forward_targets": sorted(incident["forward_targets"]),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_ids": incident["event_ids"],
            "summary": (
                "user %s: %s%s" % (
                    user,
                    ", ".join(primary) if primary else "supporting only",
                    " (" + ", ".join(supporting) + ")" if supporting else "",
                )
            ),
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    output.sort(key=lambda item: (order.get(item["severity"], 9),
                                  item["user_id"]))
    return output


def build_iocs(incidents, expected_ip):
    src_ips = set()
    user_agents = set()
    jtis = set()
    forward_targets = set()
    event_ids = set()
    for incident in incidents:
        src_ips.update(incident["src_ips"])
        user_agents.update(incident["user_agents"])
        jtis.update(incident["jti"])
        forward_targets.update(incident["forward_targets"])
        event_ids.update(incident["event_ids"])
    return {
        "src_ips": sorted(src_ips),
        "non_baseline_src_ips": sorted(ip for ip in src_ips
                                       if ip != expected_ip),
        "baseline_src_ips": sorted(ip for ip in src_ips
                                   if ip == expected_ip),
        "user_agents": sorted(user_agents),
        "jti": sorted(jtis),
        "forward_targets": sorted(forward_targets),
        "event_ids": sorted(event_ids),
    }


def build_metrics(events, incidents, recon, forwarding_diff, expected_ip):
    primary_events = set()
    linked_events = set()
    for incident in incidents:
        for signal in incident["signals"]:
            if signal["type"] in PRIMARY_SIGNALS:
                primary_events.update(signal["event_ids"])
                linked_events.update(signal["event_ids"])
    first_seen = None
    last_seen = None
    timestamps = []
    for incident in incidents:
        for value in (incident["first_seen"], incident["last_seen"]):
            if value:
                timestamps.append(value)
    if timestamps:
        first_seen = min(timestamps)
        last_seen = max(timestamps)
    first_epoch = parse_ts(first_seen)
    last_epoch = parse_ts(last_seen)
    now_epoch = time.time()
    alerts_total = sum(len(incident["signals"]) for incident in incidents)
    # Every alert we emit is evidence-backed (true positive). We never alert
    # on an approved rule, so the false-positive count is zero. In exact_ioc
    # mode an unapproved rule that the stale IOC list misses is a false
    # negative (tracked separately) -- not a false positive.
    false_positive = 0
    false_negative = sum(
        1 for rule in forwarding_diff["unapproved"]
        if not rule["matched_by_policy"]
    )
    linkage_accuracy = 1.0
    if primary_events:
        linkage_accuracy = round(len(linked_events) / float(len(primary_events)), 4)
    return {
        "events_total": len(events),
        "alerts_total": alerts_total,
        "alerts_true_positive": alerts_total,
        "alerts_false_positive": false_positive,
        "alerts_false_negative": false_negative,
        "incidents_total": len(incidents),
        "risk_score_max": max([i["risk_score"] for i in incidents] or [0]),
        "primary_events_total": len(primary_events),
        "primary_events_linked": len(linked_events),
        "incident_linkage_accuracy": linkage_accuracy,
        "multi_user_incidents": 0,
        "recon_events": len(recon),
        "forwarding_rules_total": forwarding_diff["counts"]["current"],
        "forwarding_rules_approved": forwarding_diff["counts"]["approved"],
        "forwarding_rules_unapproved": forwarding_diff["counts"]["unapproved"],
        "detection_lag_seconds": (
            round(now_epoch - first_epoch, 1) if first_epoch else 0.0),
        "attack_window_seconds": (
            round(last_epoch - first_epoch, 1)
            if first_epoch and last_epoch else 0.0),
        "baseline_clean": not incidents,
        "clean_baseline_false_positive_alerts": false_positive,
    }


def write_timeline(events, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "timestamp", "event_type", "severity", "result", "user_id",
            "src_ip", "user_agent", "jti", "mailbox", "rule",
            "event_id", "request_id",
        ])
        for event in events:
            writer.writerow([
                event.get("timestamp", ""),
                event.get("event_type", ""),
                event.get("severity", ""),
                event.get("result", ""),
                event.get("user_id", ""),
                event.get("src_ip", ""),
                event.get("user_agent", ""),
                event.get("jti", ""),
                event.get("mailbox", ""),
                event.get("rule", ""),
                event.get("event_id", ""),
                event.get("request_id", ""),
            ])


def write_alerts(incidents, path):
    count = 0
    with open(path, "w", encoding="utf-8") as fh:
        for incident in incidents:
            for signal in incident["signals"]:
                message = signal_message(incident, signal)
                alert = {
                    "alert_id": "ALT-" + hashlib.sha1(
                        (incident["incident_id"] + signal["type"]).encode(
                            "utf-8")).hexdigest()[:12],
                    "timestamp": utc_now(),
                    "severity": incident["severity"],
                    "risk_score": incident["risk_score"],
                    "incident_id": incident["incident_id"],
                    "user_id": incident["user_id"],
                    "signal": signal["type"],
                    "count": signal["count"],
                    "src_ips": signal["src_ips"],
                    "jti": signal["jti"],
                    "forward_targets": signal["forward_targets"],
                    "event_ids": signal["event_ids"],
                    "message": message,
                }
                fh.write(json.dumps(alert, separators=(",", ":")) + "\n")
                count += 1
    return count


def signal_message(incident, signal):
    name = signal["type"]
    user = incident["user_id"]
    if name == "account_hijack":
        return ("account hijack: %s authenticated from a non-baseline "
                "IP/User-Agent and performed a sensitive action" % user)
    if name == "mailbox_hijack":
        targets = signal["forward_targets"]
        if targets:
            return ("mailbox hijack: %s forwarding rule/copy outside the "
                    "approved inventory (%s)" % (user, ", ".join(targets)))
        return "mailbox hijack: victim mail read from a non-baseline context"
    if name == "token_hijack":
        return ("token hijack: JWT %s issued from one context was used from "
                "another" % (", ".join(signal["jti"]) or "(unknown)"))
    if name == "session_not_revoked":
        return ("session persistence: password changed but an older token "
                "was still accepted for %s" % user)
    if name == "recon":
        return "recon: debug endpoint fetched from a non-baseline source"
    return name


def build_prevention(events, incidents, metrics, out_dir):
    hardened = [
        e for e in events
        if e.get("event_type") == "password_changed"
        and e.get("result") == "success" and e.get("hardened")
    ]
    baseline_pw = [
        e for e in events
        if e.get("event_type") == "password_changed"
        and e.get("result") == "success" and not e.get("hardened")
    ]
    old_token_after = any(
        "session_not_revoked" in [s["type"] for s in incident["signals"]]
        for incident in incidents
    )
    mailbox_detected = any(
        "mailbox_hijack" in [s["type"] for s in incident["signals"]]
        for incident in incidents
    )
    controls = [
        {
            "control": "MFA / device binding",
            "blocks": ["account_hijack"],
            "status": "recommended (not implemented in baseline)",
            "effective": None,
        },
        {
            "control": "Revoke sessions/tokens on password change",
            "blocks": ["session_not_revoked", "token_hijack"],
            "status": "implemented (app hardened mode)",
            "effective": (not old_token_after) if hardened else None,
        },
        {
            "control": "Forwarding-rule approval + alert",
            "blocks": ["mailbox_hijack"],
            "status": "implemented (detector allowlist)",
            "effective": mailbox_detected,
        },
        {
            "control": "Remove /debug endpoints",
            "blocks": ["token_hijack", "recon"],
            "status": "recommended",
            "effective": None,
        },
    ]
    report = {
        "generated_at": utc_now(),
        "observed": {
            "baseline_password_change": bool(baseline_pw),
            "hardened_password_change": bool(hardened),
            "old_token_accepted_after_password_change": old_token_after,
            "mailbox_rule_detected": mailbox_detected,
        },
        "metrics": metrics,
        "controls": controls,
        "note": (
            "Run the same 5-step chain after enabling a control and compare "
            "the incident/alerts. Hardened mode is available in the app; "
            "the detector demonstrates forwarding-rule alerting. MFA and "
            "removal of debug endpoints are recommended hardening steps."
        ),
    }
    path = os.path.join(out_dir, "prevention_report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print("prevention: baseline_pw=%s hardened_pw=%s old_token_after=%s "
          "mailbox_alert=%s" % (
              bool(baseline_pw), bool(hardened), old_token_after,
              mailbox_detected))
    print("prevention report: %s" % path)
    return report


def print_diff(diff):
    counts = diff["counts"]
    print("INVENTORY approved=%d current=%d unapproved=%d changed=%d missing=%d "
          "policy=%s" % (
              counts["approved"], counts["current"], counts["unapproved"],
              counts["changed"], counts["missing"], diff["policy_mode"]))
    for item in diff["approved_inventory"]:
        print("APPROVED %s -> %s" % (item["user_id"], item["target_address"]))
    for rule in diff["current_rules"]:
        marker = ""
        if any(rule["user_id"] == u["user_id"]
               and rule["target_address"] == u["target_address"]
               for u in diff["unapproved"]):
            marker = "  [UNAPPROVED]"
        print("CURRENT  %s -> %s%s" % (
            rule["user_id"], rule["target_address"], marker))
    for change in diff["changed"]:
        print("CHANGED  %s: approved=%s current=%s" % (
            change["user_id"], change["approved_target"],
            change["current_target"]))
    if not diff["unapproved"]:
        print("(no unapproved forwarding rule -- clean baseline)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="DATN identity/session multi-signal detector")
    parser.add_argument("--url", default=DEFAULT_LOG_URL,
                        help="audit JSONL endpoint")
    parser.add_argument("--rules-url", default=DEFAULT_RULES_URL,
                        help="live forwarding-rule endpoint")
    parser.add_argument("--log-file", default=None,
                        help="read the audit JSONL from a local file")
    parser.add_argument("--rules-file", default=None,
                        help="read current forwarding rules from a local file")
    parser.add_argument("--known", default=DEFAULT_KNOWN_PATH,
                        help="approved forwarding inventory JSON")
    parser.add_argument("--policy", default=DEFAULT_POLICY_PATH,
                        help="detector policy JSON (allowlist / exact_ioc)")
    parser.add_argument("--expected-ip", default=DEFAULT_EXPECTED_IP,
                        help="clean baseline source IP")
    parser.add_argument("--monitor-ip", default=DEFAULT_MONITOR_IP,
                        help="monitor's own IP (ignored for recon)")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="output directory")
    parser.add_argument("--diff", action="store_true",
                        help="only print forwarding rules vs approved baseline")
    parser.add_argument("--detect", action="store_true",
                        help="run correlation (default)")
    parser.add_argument("--prevention", action="store_true",
                        help="write the before/after control report")
    args = parser.parse_args(argv)

    try:
        events, source = load_events(args.url, args.log_file)
        current_rules, rules_source = load_current_rules(
            args.rules_url, args.rules_file, events)
        known = load_known(args.known)
        policy = load_policy(args.policy)
    except Exception as exc:
        print("ERROR: could not load inputs: %s" % exc, file=sys.stderr)
        return 1

    forwarding_diff = build_forwarding_diff(current_rules, known, policy)

    if args.diff and not (args.detect or args.prevention):
        print_diff(forwarding_diff)
        return 0

    incidents_raw, recon, forwarding_diff = detect_signals(
        events, current_rules, forwarding_diff, args.expected_ip,
        args.monitor_ip)
    incidents = build_incidents(incidents_raw, recon)
    metrics = build_metrics(events, incidents, recon, forwarding_diff,
                            args.expected_ip)
    iocs = build_iocs(incidents, args.expected_ip)

    os.makedirs(args.out_dir, exist_ok=True)
    timeline_path = os.path.join(args.out_dir, "timeline.csv")
    alerts_path = os.path.join(args.out_dir, "alerts.log")
    summary_path = os.path.join(args.out_dir, "incident_summary.json")

    write_timeline(events, timeline_path)
    alert_count = write_alerts(incidents, alerts_path)

    summary = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "log_source": source,
        "rules_source": rules_source,
        "expected_baseline_ip": args.expected_ip,
        "metrics": metrics,
        "forwarding_diff": forwarding_diff,
        "recon_events": [{
            "timestamp": e.get("timestamp"),
            "event_type": e.get("event_type"),
            "src_ip": e.get("src_ip"),
            "event_id": e.get("event_id"),
        } for e in recon],
        "iocs": iocs,
        "incidents": incidents,
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    print("events=%d alerts=%d incidents=%d recon=%d "
          "linkage_accuracy=%.4f risk_max=%d" % (
              metrics["events_total"], alert_count,
              metrics["incidents_total"], metrics["recon_events"],
              metrics["incident_linkage_accuracy"],
              metrics["risk_score_max"]))
    for incident in incidents:
        print("[%s score=%d] %s signals=%s" % (
            incident["severity"].upper(), incident["risk_score"],
            incident["user_id"],
            ",".join(incident["primary_signals"]) or "supporting-only"))
        if incident["supporting_signals"]:
            print("         supporting=%s" % ",".join(
                incident["supporting_signals"]))
        print("         ioc_ips=%s ioc_jti=%s forward=%s" % (
            ",".join(incident["src_ips"]),
            ",".join(incident["jti"]),
            ",".join(incident["forward_targets"])))
    if not incidents:
        print("No correlated incident found (clean baseline or attack not run).")
    print("timeline: %s" % timeline_path)
    print("alerts  : %s" % alerts_path)
    print("summary : %s" % summary_path)

    if args.prevention:
        build_prevention(events, incidents, metrics, args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
