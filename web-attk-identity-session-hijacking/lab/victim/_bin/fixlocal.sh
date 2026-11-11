#!/bin/bash
# victim startup: enable and (re)start the baseline traffic service.
sudo systemctl enable datn-baseline.service >/dev/null 2>&1
sudo systemctl restart datn-baseline.service >/dev/null 2>&1
