#!/bin/sh
# E2: Segmentation enforced (report Section 11.5, E2; matrix tests 1, 3)
# Allow-all rules from E1 removed; lab rule set (lab_rules.yaml) loaded.
# Run on: rad-vm, vendor-vm, then bastion for the log extract.
. "$(dirname "$0")/common.sh"
start_experiment E2 "Segmentation enforced" "rad vendor bastion"
phase "lab rule set loaded, NO allow-all rules"

case "$ROLE" in
  rad)
    mark_time "E2 F2 attempt: radiology to EMR DB 1433"
    run "nmap -sS -Pn -p 1433 192.168.10.20"                 # expect filtered (G-03)
    run "curl -sS -m 5 -o /dev/null -w 'http=%{http_code}\n' http://192.168.10.21:443/"   # expect works (R-03)
    run "nc -s 192.168.40.12  -zv -w 5 192.168.10.40 2575"   # expect works: PACS broker (R-02)
    run "nc -s 192.168.40.100 -zv -w 5 192.168.10.40 2575"   # expect timeout: not the broker
    ;;
  vendor)
    mark_time "E2 F3 attempt: vendor to HIS 1433/2575/3389"
    run "nmap -sS -Pn -p 1433,2575,3389 192.168.10.20"       # expect filtered (VW-01 / G-03)
    run "nmap -sS -Pn -p 443,22 192.168.30.0/28"             # expect filtered (VW-01)
    run "curl -sS -m 5 -I https://example.com"               # expect works (VW-02)
    ;;
  bastion)
    run "grep -E '192\.168\.40\.100' /var/log/opnsense.log | grep -i block | tail -20"
    ;;
  *) no_steps "rad-vm, vendor-vm, bastion" ;;
esac
finish
