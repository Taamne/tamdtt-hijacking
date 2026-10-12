#!/bin/bash
# victim-mail startup: ensure log dir, enable + (re)start services.
# Services are systemd units so they also survive plain container
# restarts (e.g. after checkwork), where fixlocal does NOT rerun.
LOG_DIR=/var/log/victim-mail
sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1
sudo chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
sudo systemctl enable victim-webmail.service >/dev/null 2>&1
sudo systemctl enable victim-legacy.service >/dev/null 2>&1
sudo systemctl restart victim-webmail.service >/dev/null 2>&1
sudo systemctl restart victim-legacy.service >/dev/null 2>&1
# Wait until both services answer so students never race the boot.
for i in $(seq 1 30); do
    if curl -s -o /dev/null http://127.0.0.1:8000/login \
        && (echo > /dev/tcp/127.0.0.1/2323) >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
