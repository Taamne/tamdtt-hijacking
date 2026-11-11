#!/bin/bash
# Victim baseline traffic generator.
#
# Simulates the legitimate employee user01:
#   1. logs in from 172.26.0.4 (the clean baseline),
#   2. opens the profile and the mailbox,
#   3. requests a JWT and keeps using it against /api/me.
#
# This is what makes the "normal" source IP (172.26.0.4) and a live victim
# token visible in /debug/sessions for the hijacking demo.
HOST=${PORTAL_HOST:-victim-portal}
PORT=${PORTAL_PORT:-8000}
BASE="http://$HOST:$PORT"
JAR=/home/ubuntu/victim.jar
TOKEN_FILE=/home/ubuntu/victim.jwt
USER='user01@datn.local'
PASS='Us3r01_DATN!2026'

sleep 10
rm -f "$JAR" "$TOKEN_FILE"

# Wait for the portal, then log in as the victim.
for i in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" \
        --data-urlencode "username=$USER" \
        --data-urlencode "password=$PASS" \
        "$BASE/login")
    if [ "$code" = "303" ] || [ "$code" = "302" ]; then
        break
    fi
    sleep 2
done

# Issue the victim JWT once; refresh only if it stops working.
for i in $(seq 1 30); do
    if curl -s -b "$JAR" -c "$JAR" -X POST "$BASE/api/token" \
        -o /tmp/datn_token.json; then
        jq -r '.access_token // empty' /tmp/datn_token.json > "$TOKEN_FILE"
        [ -s "$TOKEN_FILE" ] && break
    fi
    sleep 2
done

while true; do
    curl -s -b "$JAR" -c "$JAR" "$BASE/profile" -o /dev/null
    curl -s -b "$JAR" -c "$JAR" "$BASE/mail/inbox" -o /dev/null
    if [ -s "$TOKEN_FILE" ]; then
        code=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
            "$BASE/api/me")
        if [ "$code" != "200" ]; then
            curl -s -b "$JAR" -c "$JAR" -X POST "$BASE/api/token" \
                -o /tmp/datn_token.json
            jq -r '.access_token // empty' /tmp/datn_token.json > "$TOKEN_FILE"
        fi
    fi
    sleep 25
done
