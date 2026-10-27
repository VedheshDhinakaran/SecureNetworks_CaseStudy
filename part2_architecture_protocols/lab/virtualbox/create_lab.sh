#!/usr/bin/env bash
# =====================================================================
#  Build the CS07 lab in VirtualBox (report Ch. 11, Figure 11.1)
#  Creates: opnsense (6 NICs) + his-vm, pump-vm, rad-vm, vendor-vm
#
#  Usage:
#    ./create_lab.sh /path/to/OPNsense-25.x-dvd-amd64.iso /path/to/alpine-virt-3.20.x-x86_64.iso
#
#  Safe to re-run: existing VMs with the same name are left alone.
#  Windows users: use create_lab.ps1 in this folder instead.
# =====================================================================
set -euo pipefail

OPN_ISO="${1:-}"
ALPINE_ISO="${2:-}"
if [[ -z "$OPN_ISO" || -z "$ALPINE_ISO" ]]; then
  echo "usage: $0 <opnsense.iso> <alpine-virt.iso>" >&2
  exit 1
fi
for f in "$OPN_ISO" "$ALPINE_ISO"; do
  [[ -f "$f" ]] || { echo "not found: $f (unpack the OPNsense .iso.bz2 first)" >&2; exit 1; }
done
command -v VBoxManage >/dev/null || { echo "VBoxManage not on PATH; install VirtualBox 7" >&2; exit 1; }

VM_DIR="$(VBoxManage list systemproperties | awk -F': +' '/Default machine folder/ {print $2}')"
HOSTONLY_IP="192.168.90.5"      # the host acts as bastion / log collector

exists() { VBoxManage list vms | grep -q "\"$1\""; }

# ---------------------------------------------------------------- MGMT
# Host-only network for the MGMT zone. VirtualBox 7 on Linux/macOS may
# need 192.168.90.0/24 allowed in /etc/vbox/networks.conf:
#   * 192.168.90.0/24
HOSTONLY_IF="$(VBoxManage list hostonlyifs | awk '/^Name:/ {n=$2} /IPAddress: +192\.168\.90\.5/ {print n}' | head -1)"
if [[ -z "$HOSTONLY_IF" ]]; then
  HOSTONLY_IF="$(VBoxManage hostonlyif create | sed -n "s/.*Interface '\(.*\)'.*/\1/p")"
  VBoxManage hostonlyif ipconfig "$HOSTONLY_IF" --ip "$HOSTONLY_IP" --netmask 255.255.255.0
fi
echo "[+] MGMT host-only interface: $HOSTONLY_IF ($HOSTONLY_IP)"

# ------------------------------------------------------------ helpers
make_vm() {   # name ostype ram_mb cpus disk_mb iso
  local name="$1" ostype="$2" ram="$3" cpus="$4" disk="$5" iso="$6"
  if exists "$name"; then echo "[=] $name already exists, skipping"; return 1; fi
  echo "[+] creating $name"
  VBoxManage createvm --name "$name" --ostype "$ostype" --register >/dev/null
  VBoxManage modifyvm "$name" --memory "$ram" --cpus "$cpus" --firmware bios \
      --boot1 disk --boot2 dvd --audio-enabled off --usb off
  VBoxManage createmedium disk --filename "$VM_DIR/$name/$name.vdi" --size "$disk" >/dev/null
  VBoxManage storagectl "$name" --name SATA --add sata --controller IntelAhci
  VBoxManage storageattach "$name" --storagectl SATA --port 0 --device 0 --type hdd --medium "$VM_DIR/$name/$name.vdi"
  VBoxManage storageattach "$name" --storagectl SATA --port 1 --device 0 --type dvddrive --medium "$iso"
  return 0
}

# ----------------------------------------------------------- firewall
if make_vm opnsense FreeBSD_64 4096 2 20480 "$OPN_ISO"; then
  # em0 WAN, em1 LAN(MGMT), em2 HIS, em3 DEVICES, em4 RADIOLOGY, em5 VENDOR
  VBoxManage modifyvm opnsense \
    --nic1 nat \
    --nic2 hostonly --host-only-adapter2 "$HOSTONLY_IF" \
    --nic3 intnet --intnet3 sjv-his \
    --nic4 intnet --intnet4 sjv-devices \
    --nic5 intnet --intnet5 sjv-radiology \
    --nic6 intnet --intnet6 sjv-vendor
  for i in 1 2 3 4 5 6; do VBoxManage modifyvm opnsense --nic-type$i 82540EM; done
  # Promiscuous mode is needed on internal networks for IPS (netmap) to see traffic
  for i in 3 4 5 6; do VBoxManage modifyvm opnsense --nic-promisc$i allow-all; done
fi

# ---------------------------------------------------------- zone VMs
declare -A ZONES=( [his-vm]=sjv-his [pump-vm]=sjv-devices [rad-vm]=sjv-radiology [vendor-vm]=sjv-vendor )
for vm in his-vm pump-vm rad-vm vendor-vm; do
  if make_vm "$vm" Linux_64 512 1 2048 "$ALPINE_ISO"; then
    VBoxManage modifyvm "$vm" --nic1 intnet --intnet1 "${ZONES[$vm]}" --nic-type1 82540EM
  fi
done

cat <<MSG

Lab VMs created. Next steps (report Section 11.4):
  1. Start 'opnsense', log in as 'installer' / 'opnsense', install to disk, reboot.
  2. Console option 1: assign em0=WAN em1=LAN em2..em5=OPT1..OPT4.
     Console option 2: set LAN to 192.168.90.1/24.
  3. Install Alpine on each zone VM (setup-alpine), then run the matching
     script from ../hosts/ (setup_his.sh, setup_pump.sh, setup_rad.sh, setup_vendor.sh).
  4. Load aliases and rules: part3_rulebase_policy/opnsense/
MSG
