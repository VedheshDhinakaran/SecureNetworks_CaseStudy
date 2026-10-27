#!/bin/sh
# Evidence preservation, step 1 of every playbook (report Ch. 13):
# export BEFORE adding any containment rule, so nothing is overwritten.
#
#   ./collect_evidence.sh <case-id> <suspect-ip> [suspect-ip ...]
#
# Run on the bastion. Produces cases/<case-id>/ with a SHA-256 manifest
# and a chain-of-custody note the handler signs.
set -eu
CASE="${1:?usage: $0 <case-id> <suspect-ip> [...]}"; shift
[ $# -ge 1 ] || { echo "give at least one suspect IP" >&2; exit 1; }
FW="${FW:-192.168.90.1}"
LOG="${LOG:-/var/log/opnsense.log}"
DIR="cases/$CASE"
mkdir -p "$DIR"
NOW="$(date -Iseconds)"

ssh -o BatchMode=yes "root@$FW" 'pfctl -ss -v'  > "$DIR/states.txt"
ssh -o BatchMode=yes "root@$FW" 'pfctl -vvsr'   > "$DIR/rules_counters.txt"
ssh -o BatchMode=yes "root@$FW" 'cat /tmp/rules.debug' > "$DIR/rules.debug"
ssh -o BatchMode=yes "root@$FW" 'cat /conf/config.xml' > "$DIR/config.xml"
ssh -o BatchMode=yes "root@$FW" 'arp -an'       > "$DIR/arp.txt"
for ip in "$@"; do
  esc="$(echo "$ip" | sed 's/\./\\./g')"
  grep -E "$esc" "$LOG" > "$DIR/log_$ip.txt" || true
  ssh -o BatchMode=yes "root@$FW" "pfctl -ss | grep -F '$ip'" > "$DIR/states_$ip.txt" || true
done

( cd "$DIR" && sha256sum * > SHA256SUMS )
cat > "$DIR/CUSTODY.txt" <<NOTE
Case:        $CASE
Collected:   $NOW by $(id -un) on $(hostname)
Suspects:    $*
Files:       see SHA256SUMS (hashes taken at collection time)
config.xml contains secrets: store this folder encrypted, never attach it to a ticket.

Handler signature: ____________________   Received by: ____________________
NOTE
echo "[+] evidence in $DIR (contains config.xml: handle as confidential)"
