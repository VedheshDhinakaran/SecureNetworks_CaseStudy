#!/bin/sh
# E7: Application identification on 443 (matrix test 8)
# his-vm: stop the web server on .21:443 and start sshd there.
# rad-vm: try ssh -p 443 with Zenarmor off and on.
. "$(dirname "$0")/common.sh"
start_experiment E7 "App-ID: SSH on 443" "his rad"

case "$ROLE" in
  his)
    run "pkill -f 'emr_app.py' ; pkill -f 'http.server 443' ; true"
    run "/usr/sbin/sshd -o ListenAddress=192.168.10.21 -p 443"
    run "netstat -tln | grep ':443'"
    echo "[i] When finished: pkill -f 'sshd -o ListenAddress=192.168.10.21' and restart the EMR app."
    ;;
  rad)
    phase "Zenarmor OFF (or not attached to RADIOLOGY)"
    run "ssh -p 443 -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no test@192.168.10.21 true; echo ssh_rc=\$?"
    run "nc -w 5 192.168.10.21 443 </dev/null | head -1"   # SSH banner = session got through
    phase "Zenarmor ON (policy blocks SSH and Remote Access on RADIOLOGY)"
    run "ssh -p 443 -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no test@192.168.10.21 true; echo ssh_rc=\$?"
    run "nc -w 5 192.168.10.21 443 </dev/null | head -1"
    ;;
  *) no_steps "his-vm, rad-vm" ;;
esac
finish
echo "[i] If the free Zenarmor edition limits this, write down exactly what it allowed. That is a valid result."
