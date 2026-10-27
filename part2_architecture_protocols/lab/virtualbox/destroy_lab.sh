#!/usr/bin/env bash
# Remove all CS07 lab VMs and their disks. Asks before deleting.
set -euo pipefail
VMS=(opnsense his-vm pump-vm rad-vm vendor-vm)
read -r -p "Delete ${VMS[*]} and their disks? [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || exit 0
for vm in "${VMS[@]}"; do
  if VBoxManage list vms | grep -q "\"$vm\""; then
    VBoxManage controlvm "$vm" poweroff 2>/dev/null || true
    VBoxManage unregistervm "$vm" --delete && echo "[-] removed $vm"
  fi
done
