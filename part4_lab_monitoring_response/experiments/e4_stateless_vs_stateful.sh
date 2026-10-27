#!/bin/sh
# E4: Stateless versus stateful (report Section 11.5, E4; Table 3.x "five failures")
# Four phases, each needing a GUI change on OPNsense first. Run the same
# script on rad-vm, his-vm and the bastion; each does its part per phase.
. "$(dirname "$0")/common.sh"
start_experiment E4 "Stateless vs stateful" "rad his bastion"

case "$ROLE" in
  rad)
    phase "STEP 1: R-03 state type NONE + floating HIS-out no-state rule; NO reverse rule"
    run "curl -sS -m 8 -o /dev/null -w 'http=%{http_code}\n' http://192.168.10.21:443/"   # expect timeout
    phase "STEP 2: reverse rule added (HIS: H_EMR_APP:443 -> RADIOLOGY net, state none)"
    run "curl -sS -m 8 -o /dev/null -w 'http=%{http_code}\n' http://192.168.10.21:443/"   # expect works
    echo "[i] Leave 'nc -lk -p 8080' running in another shell for step 3."
    phase "STEP 3: his-vm is about to scan us from source port 443"
    phase "STEP 4: keep state restored, reverse + floating rules deleted"
    run "curl -sS -m 8 -o /dev/null -w 'http=%{http_code}\n' http://192.168.10.21:443/"   # expect works
    ;;
  his)
    phase "STEP 3: reverse rule still present, rad-vm listening on 8080"
    run "nmap -sS -Pn -g 443 -S 192.168.10.21 -e eth0 -p 8080 192.168.40.100"   # expect OPEN (abuse)
    phase "STEP 4: keep state restored, reverse + floating rules deleted"
    run "nmap -sS -Pn -g 443 -S 192.168.10.21 -e eth0 -p 8080 192.168.40.100"   # expect filtered
    ;;
  bastion)
    phase "STEP 1 capture: start BEFORE rad-vm runs curl"
    fw "timeout 20 tcpdump -ni em2 -c 20 host 192.168.10.21 and port 443"
    phase "STEP 4: after rad-vm curl, show the state entry"
    fw "pfctl -ss | grep 192.168.10.21"
    ;;
  *) no_steps "rad-vm, his-vm, bastion" ;;
esac
finish
