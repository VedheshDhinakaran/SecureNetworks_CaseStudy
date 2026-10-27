#!/bin/sh
# Weekly / monthly snapshot of firewall state for the hit-counter review
# (report Section 10.2) and the monitoring calendar. Run on the bastion.
#   ./snapshot_firewall.sh [outdir]
set -eu
FW="${FW:-192.168.90.1}"
OUT="${1:-./snapshots}/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$OUT"
ssh -o BatchMode=yes "root@$FW" 'pfctl -vvsr' > "$OUT/pfctl_vvsr.txt"
ssh -o BatchMode=yes "root@$FW" 'pfctl -si'   > "$OUT/pfctl_si.txt"
ssh -o BatchMode=yes "root@$FW" 'pfctl -ss | wc -l' > "$OUT/state_count.txt"
ssh -o BatchMode=yes "root@$FW" 'cat /tmp/rules.debug' > "$OUT/rules.debug"
( cd "$OUT" && sha256sum * > SHA256SUMS )
echo "[+] snapshot in $OUT"
echo "    python3 ../../part3_rulebase_policy/tools/hit_counter_review.py $OUT/pfctl_vvsr.txt --rules-debug $OUT/rules.debug --baseline <previous>/pfctl_vvsr.txt"
