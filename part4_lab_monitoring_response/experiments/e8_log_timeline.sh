#!/bin/sh
# E8: Rebuilding an incident from logs (matrix test 15)
# Step 1 (rad-vm, vendor-vm): repeat the F2 / F3 attempts; times are marked
#         in $RESULTS/attempt_times.csv.
# Step 2 (bastion): pull the remote log and build the timeline.
. "$(dirname "$0")/common.sh"
start_experiment E8 "Incident timeline from logs" "rad vendor bastion"
TOOLS="$(cd "$(dirname "$0")/../tools" && pwd)"

case "$ROLE" in
  rad)
    for i in 1 2 3; do
      mark_time "F2 attempt $i: radiology to EMR DB 1433"
      run "nc -zv -w 3 192.168.10.20 1433"
      sleep 20
    done
    ;;
  vendor)
    for i in 1 2 3; do
      mark_time "F3 attempt $i: vendor sweep of HIS"
      run "nmap -sS -Pn -p 1433,2575,3389 --max-retries 0 192.168.10.20,21,40"
      sleep 20
    done
    ;;
  bastion)
    run "grep -E '192\.168\.40\.100|10\.61\.0\.' /var/log/opnsense.log | grep filterlog | grep block | tail -50"
    run "grep filterlog /var/log/opnsense.log > $RESULTS/E8/filterlog_extract.log"
    run "ssh -o BatchMode=yes root@$FW 'cat /tmp/rules.debug' > $RESULTS/E8/rules_debug.txt"
    echo "[i] Copy attempt_times.csv from rad-vm and vendor-vm (collect_results.sh), then:"
    echo "    python3 $TOOLS/timeline.py $RESULTS/E8/filterlog_extract.log --rules-debug $RESULTS/E8/rules_debug.txt \\"
    echo "        --src 192.168.40.100 --src 10.61.0.0/24 --action block --marks attempt_times.csv"
    ;;
  *) no_steps "rad-vm, vendor-vm, bastion" ;;
esac
finish
