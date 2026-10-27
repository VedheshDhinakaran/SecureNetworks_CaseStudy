#!/usr/bin/env bash
# Take (or restore) a named snapshot of every lab VM, so each experiment
# can start from the same known state.
#   ./snapshot_lab.sh take  before-E1
#   ./snapshot_lab.sh restore before-E1
set -euo pipefail
action="${1:?take|restore}"; name="${2:?snapshot name}"
for vm in opnsense his-vm pump-vm rad-vm vendor-vm; do
  case "$action" in
    take)    VBoxManage snapshot "$vm" take "$name" --live && echo "[+] $vm: $name" ;;
    restore) VBoxManage controlvm "$vm" poweroff 2>/dev/null || true
             VBoxManage snapshot "$vm" restore "$name" && echo "[+] $vm restored to $name" ;;
    *) echo "unknown action $action" >&2; exit 1 ;;
  esac
done
