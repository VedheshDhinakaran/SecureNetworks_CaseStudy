#!/bin/sh
# E3: Device zone has three flows and nothing else (matrix tests 4, 5)
# Run on: pump-vm, then bastion (rule counters).
. "$(dirname "$0")/common.sh"
start_experiment E3 "Device zone: three flows only" "pump bastion"

case "$ROLE" in
  pump)
    run "dig @192.168.10.53 emr.sjv.local +short"             # DV-01 UDP
    run "dig +tcp @192.168.10.53 emr.sjv.local +short"        # DV-01 TCP
    run "chronyd -Q 'server 192.168.10.57 iburst'"            # DV-02
    run "nc -zv -w 5 192.168.10.40 2575"                      # DV-03
    run "python3 /opt/sjv/lab/services/mllp_client.py --host 192.168.10.40"   # real HL7 ORU over DV-03
    run "nc -zv -w 3 192.168.10.20 1433"                      # expect fail (G-03)
    run "curl -sS -m 5 -o /dev/null https://example.com"      # expect fail (DV-05)
    run "nmap -sn 192.168.40.0/24"                            # expect 0 hosts up
    ;;
  bastion)
    fw "pfctl -vvsr | head -5"
    run "ssh -o BatchMode=yes root@$FW 'pfctl -vvsr' > $RESULTS/E3/pfctl_vvsr_$(date +%Y%m%dT%H%M%S).txt"
    run "ssh -o BatchMode=yes root@$FW 'cat /tmp/rules.debug' > $RESULTS/E3/rules_debug.txt"
    echo "[i] Then: python3 ../../part3_rulebase_policy/tools/hit_counter_review.py <pfctl file> --rules-debug $RESULTS/E3/rules_debug.txt --only DV-0"
    ;;
  *) no_steps "pump-vm, bastion" ;;
esac
finish
