#!/bin/bash
# B5 helper: the legitimate victim changes user01's password.
#
# Usage:
#   ./change_password_baseline.sh            # baseline: keep old sessions/tokens
#   ./change_password_baseline.sh hardened   # revoke every session/token
#
# Run this in the *victim* terminal after the baseline login has completed
# (the cookie jar must exist).  The attacker then replays the old JWT.
HOST=${PORTAL_HOST:-victim-portal}
PORT=${PORTAL_PORT:-8000}
BASE="http://$HOST:$PORT"
JAR=/home/ubuntu/victim.jar
OLD='Us3r01_DATN!2026'
NEW='N3w_Us3r01!2026'
MODE=${1:-baseline}

if [ "$MODE" = "hardened" ]; then
    HARDENED=1
else
    HARDENED=0
fi

if [ ! -s "$JAR" ]; then
    echo "No victim cookie jar at $JAR yet."
    echo "Wait for the baseline login (about 10-20 seconds) and retry."
    exit 1
fi

code=$(curl -s -o /tmp/datn_pw.out -w '%{http_code}' \
    -b "$JAR" -c "$JAR" \
    --data-urlencode "current_password=$OLD" \
    --data-urlencode "new_password=$NEW" \
    --data-urlencode "hardened=$HARDENED" \
    "$BASE/password")

echo "password change HTTP status: $code"
if grep -q "Baseline mode" /tmp/datn_pw.out; then
    echo "baseline: old web session AND old JWT remain valid"
elif grep -q "Hardened mode" /tmp/datn_pw.out; then
    echo "hardened: all sessions and API tokens were revoked"
elif grep -q "Current password is incorrect" /tmp/datn_pw.out; then
    echo "current password is incorrect (was it already changed in this run?)"
    echo "reset with: labtainer -r web-attk-identity-session-hijacking"
else
    echo "unexpected response; see /tmp/datn_pw.out"
fi
