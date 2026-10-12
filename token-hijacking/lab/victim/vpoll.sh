#!/bin/bash
# victim portal user: logs in once, then polls /profile to keep the
# session alive (so there is always a live victim token to hijack).
# Cookie jar persists the bearer token across polls.
HOST=${1:-victim-portal}
PORT=8000
JAR=/home/ubuntu/victim.jar
sleep 12
rm -f "$JAR"
curl -s -c "$JAR" -d "username=victim&password=Vict1m_Token!2026" \
    "http://$HOST:$PORT/login" -o /dev/null
while true; do
    curl -s -b "$JAR" -c "$JAR" "http://$HOST:$PORT/profile" -o /dev/null
    sleep 25
done
