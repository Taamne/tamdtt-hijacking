#!/bin/bash
# victim-mail startup: webmail (Flask :8000) + SSH for the SOC log pull.
# Runs as the container user ($1 is the user password for sudo).
# Everything runs as systemd units so services also survive plain
# container restarts (e.g. after checkwork), where fixlocal does NOT rerun.
APP_DIR=/home/ubuntu/webapp
LOG_DIR=/var/log/victim-mail
if [ -n "$1" ]; then
    echo "$1" | sudo -S mkdir -p "$LOG_DIR" >/dev/null 2>&1
    echo "$1" | sudo -S chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
else
    sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1
    sudo chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
fi
# SSH host keys + analyst public key (log-shipping trust).
sudo /usr/bin/ssh-keygen -A >/dev/null 2>&1
mkdir -p /home/ubuntu/.ssh
cat /home/ubuntu/webapp/soc_id.pub >> /home/ubuntu/.ssh/authorized_keys 2>/dev/null
sort -u /home/ubuntu/.ssh/authorized_keys -o /home/ubuntu/.ssh/authorized_keys 2>/dev/null
chmod 700 /home/ubuntu/.ssh
chmod 600 /home/ubuntu/.ssh/authorized_keys
sudo systemctl enable victim-webmail.service >/dev/null 2>&1
sudo systemctl enable victim-sshd.service >/dev/null 2>&1
sudo systemctl restart victim-webmail.service >/dev/null 2>&1
sudo systemctl restart victim-sshd.service >/dev/null 2>&1
# Wait until the portal answers so nothing races the boot.
for i in $(seq 1 30); do
    if curl -s -o /dev/null http://127.0.0.1:8000/login; then
        break
    fi
    sleep 1
done
