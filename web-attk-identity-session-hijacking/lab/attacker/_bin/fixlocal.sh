#!/bin/bash
# attacker startup: prepare writable Firefox profile directories.
# Labtainer terminals run as root (HOME=/home/ubuntu), while the
# /usr/local/bin/firefox wrapper switches root to HOME=/root.
mkdir -p /root/.mozilla /home/ubuntu/.mozilla >/dev/null 2>&1
chown -R ubuntu:ubuntu /home/ubuntu/.mozilla >/dev/null 2>&1
