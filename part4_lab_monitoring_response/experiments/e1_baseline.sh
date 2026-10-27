#!/bin/sh
# E1: Baseline - the old flat network (report Section 11.5, E1)
# Before running: put "Pass any -> any" at the TOP of the RADIOLOGY and
# VENDOR interface rules to mimic the old vendor any-any rule.
# Run on: rad-vm, vendor-vm.  Expected: 1433 open from radiology (F2);
# vendor laptop sees HIS and device hosts (F3).
. "$(dirname "$0")/common.sh"
start_experiment E1 "Baseline (allow-all in place)" "rad vendor"
phase "allow-all rule at the top of RADIOLOGY and VENDOR"

case "$ROLE" in
  rad)
    run "nmap -sS -Pn -p 1433,2575,443 192.168.10.20-40"
    mark_time "E1 radiology to EMR DB 1433 (allow-all)"
    run "nc -zv -w 3 192.168.10.20 1433"
    ;;
  vendor)
    run "nmap -sS -Pn -p 1433,2575,443,22 192.168.10.0/24 192.168.30.0/24"
    mark_time "E1 vendor sweep of HIS and DEVICES (allow-all)"
    ;;
  *) no_steps "rad-vm, vendor-vm" ;;
esac
finish
echo "[!] Remove the allow-all rules before E2."
