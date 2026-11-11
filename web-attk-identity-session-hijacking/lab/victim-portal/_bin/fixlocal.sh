#!/bin/bash
# victim-portal startup: ensure the audit log directory exists, then
# enable and (re)start the portal service.
LOG_DIR=/var/log/datn
sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1
sudo chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
sudo systemctl enable datn-portal.service >/dev/null 2>&1
sudo systemctl restart datn-portal.service >/dev/null 2>&1
# Wait until the portal answers so nobody races the boot.
for i in $(seq 1 40); do
    if curl -s -o /dev/null http://127.0.0.1:8000/health; then
        break
    fi
    sleep 1
done
