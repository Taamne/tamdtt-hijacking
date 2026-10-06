#!/bin/bash
# victim-web startup: launch the Flask portal (idempotent).
# Runs as the container user ($1 is the user password for sudo).
APP_DIR=/home/ubuntu/webapp
LOG_DIR=/var/log/victim-web
if [ -n "$1" ]; then
    echo "$1" | sudo -S mkdir -p "$LOG_DIR" >/dev/null 2>&1
    echo "$1" | sudo -S chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
else
    sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1
    sudo chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
fi
export VICTIM_LOG="$LOG_DIR/app.log"
if ! pgrep -f "webapp/app.py" >/dev/null 2>&1; then
    cd "$APP_DIR" || exit 1
    nohup python3 app.py >>app.out 2>&1 &
fi
# Wait until the portal answers so students never race the boot.
for i in $(seq 1 30); do
    if curl -s -o /dev/null http://127.0.0.1:8000/login; then
        break
    fi
    sleep 1
done
