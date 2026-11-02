#!/bin/bash
# analyst startup: ensure the SOC alert directory exists and is writable.
# No daemons here: the analyst pulls evidence on demand (fetch_logs.sh)
# and runs the detector by hand (detect.py) -- like a real SOC workstation.
LOG_DIR=/var/log/soc
sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1
sudo chown ubuntu:ubuntu "$LOG_DIR" >/dev/null 2>&1
