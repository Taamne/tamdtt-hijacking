#!/bin/bash
# fetch_logs.sh -- pull SOC evidence from victim-mail over scp.
# Uses the baked analyst keypair; no password needed.
set -u
KEY=/home/ubuntu/ssh_keys/id_soc
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i $KEY"
SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i $KEY"
chmod 600 "$KEY" 2>/dev/null
mkdir -p /home/ubuntu/collected
$SCP "ubuntu@victim-mail:/var/log/victim-mail/mail.log" /home/ubuntu/collected/mail.log
$SCP "ubuntu@victim-mail:/home/ubuntu/webapp/mail.db" /home/ubuntu/collected/mail.db
echo "--- collected ---"
ls -la /home/ubuntu/collected/
