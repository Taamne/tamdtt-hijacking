#!/bin/bash
# victim mailbox checker: simulates the employee polling their mailbox
# over the legacy UNENCRYPTED mail-check protocol. Credentials travel
# in clear text on the wire -- that is the vulnerability of this lab.
# Each poll runs in a subshell so a failed redirection can never kill
# the outer infinite loop.
HOST=${1:-victim-mail}
PORT=2323
USER=victim
PASS=Vict1m_Mail!2026
sleep 12
while true; do
    (
        exec 3<>/dev/tcp/$HOST/$PORT 2>/dev/null || exit 1
        read -t 5 _banner <&3 || true
        read -t 5 _p1 <&3 || true
        printf '%s\n' "$USER" >&3 || exit 1
        read -t 5 _p2 <&3 || true
        printf '%s\n' "$PASS" >&3 || exit 1
        timeout 5 cat <&3 >/dev/null 2>&1 || true
    ) >/dev/null 2>&1 || true
    sleep 25
done
