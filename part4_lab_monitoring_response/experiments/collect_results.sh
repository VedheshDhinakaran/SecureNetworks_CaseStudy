#!/bin/sh
# Run on the bastion (192.168.90.5). Pulls every transcript from the zone
# VMs into ../evidence/raw/<vm>/ over SSH (allowed by the M-01 lab rule)
# and writes SHA-256 sums so later edits would be visible.
set -eu
DEST="$(cd "$(dirname "$0")/.." && pwd)/evidence/raw"
VMS="his:192.168.10.20 rad:192.168.40.100 pump:192.168.30.10"
[ -n "${VENDOR_IP:-}" ] && VMS="$VMS vendor:$VENDOR_IP"
mkdir -p "$DEST"
for entry in $VMS; do
  name="${entry%%:*}"; ip="${entry#*:}"
  mkdir -p "$DEST/$name"
  echo "[*] $name ($ip)"
  scp -o BatchMode=yes -o ConnectTimeout=5 -r "root@$ip:/opt/sjv/results/*" "$DEST/$name/" || echo "    [!] could not reach $name"
done
[ -d /opt/sjv/results ] && mkdir -p "$DEST/bastion" && cp -r /opt/sjv/results/. "$DEST/bastion/" 2>/dev/null || true
( cd "$DEST" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2 > SHA256SUMS )
echo "[+] collected into $DEST (set VENDOR_IP=10.61.0.x to include vendor-vm)"
