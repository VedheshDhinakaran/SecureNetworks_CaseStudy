#!/usr/bin/env bash
# Replay a capture taken in the lab through Suricata with our local rules,
# so rule changes can be tested on the bastion without touching the firewall.
#
#   ./run_suricata_offline.sh <capture.pcap> [extra.rules ...]
#
# Output goes to ./offline_out/<pcap name>/ (eve.json, fast.log). Then:
#   python3 ../../tools/eve_summary.py offline_out/<name>/eve.json
#
# The capture must be one the team took (tcpdump on the firewall or a VM).
set -euo pipefail
PCAP="${1:?usage: $0 <capture.pcap> [extra.rules ...]}"; shift || true
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/offline_out/$(basename "${PCAP%.*}")"
mkdir -p "$OUT"
command -v suricata >/dev/null || { echo "install suricata first (apt install suricata / brew install suricata)" >&2; exit 1; }

RULES=("$HERE/sjv-custom.rules" "$@")
echo "[*] syntax check"
for r in "${RULES[@]}"; do suricata -T -S "$r" -l "$OUT" >/dev/null; done
echo "[*] replaying $PCAP"
suricata -r "$PCAP" -k none -l "$OUT" $(printf -- '-S %s ' "${RULES[@]}") \
  --set "vars.address-groups.HOME_NET=[192.168.0.0/16,10.0.0.0/8]"
echo "[+] alerts: $(grep -c '"event_type":"alert"' "$OUT/eve.json" || true)  ->  $OUT/eve.json"
