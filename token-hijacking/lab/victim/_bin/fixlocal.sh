#!/bin/bash
# victim startup: enable + (re)start the session keeper service,
# so a live victim token always exists (and survives restarts).
sudo systemctl enable vpoll.service >/dev/null 2>&1
sudo systemctl restart vpoll.service >/dev/null 2>&1
