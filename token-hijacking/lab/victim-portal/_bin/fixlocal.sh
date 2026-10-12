#!/bin/bash
# victim-portal startup: ensure log dir, enable + (re)start service.
# systemd unit keeps the portal alive across plain container restarts
# (e.g. after checkwork), where fixlocal does NOT rerun.
LOG_DIR=/var/log/victim-portal
sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1
sudo chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
sudo systemctl enable victim-portal.service >/dev/null 2>&1
sudo systemctl restart victim-portal.service >/dev/null 2>&1
# Wait until the portal answers so students never race the boot.
for i in $(seq 1 30); do
    if curl -s -o /dev/null http://127.0.0.1:8000/login; then
        break
    fi
    sleep 1
done
