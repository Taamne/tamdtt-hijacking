#!/bin/bash
# victim startup: enable + (re)start the polling loop as a service,
# so it survives plain container restarts (e.g. after checkwork).
sudo systemctl enable vcheck.service >/dev/null 2>&1
sudo systemctl restart vcheck.service >/dev/null 2>&1
