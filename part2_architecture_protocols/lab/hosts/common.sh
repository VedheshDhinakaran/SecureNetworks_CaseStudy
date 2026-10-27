#!/bin/sh
# Shared helpers for the Alpine zone hosts. Sourced by setup_*.sh.
# Alpine uses /bin/sh (busybox ash), so keep this POSIX.
set -eu

TOOLS="nmap nmap-scripts tcpdump tshark netcat-openbsd curl bind-tools chrony openssh-client python3 iproute2 jq"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }; }

install_tools() {
  echo "[+] installing tools (needs temporary internet access, see README 'setup mode')"
  # community repo carries tshark
  sed -i 's/^#\(.*\/community\)$/\1/' /etc/apk/repositories
  apk update
  # shellcheck disable=SC2086
  apk add $TOOLS "$@"
  # sshd lets the bastion (192.168.90.5) pull experiment results; the
  # M-01 lab rule allows MGMT -> zones, the zone rules never allow the reverse.
  if apk info -e openssh-server >/dev/null 2>&1; then
    rc-update add sshd default >/dev/null 2>&1 || true
    rc-service sshd start || true
  fi
}

write_static() {   # write_static <primary/prefix> <gateway> [extra/prefix ...]
  primary="$1"; gw="$2"; shift 2
  {
    echo "auto lo"; echo "iface lo inet loopback"; echo
    echo "auto eth0"; echo "iface eth0 inet static"
    echo "    address $primary"; echo "    gateway $gw"
    for extra in "$@"; do echo "    up ip addr add $extra dev eth0"; done
  } > /etc/network/interfaces
  rc-service networking restart || true
}

write_dhcp() {
  printf 'auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n' > /etc/network/interfaces
  rc-service networking restart || true
}

set_resolver() { printf 'nameserver %s\n' "$1" > /etc/resolv.conf; }

enable_local_start() {   # enable_local_start <name> <<script on stdin>>
  cat > "/etc/local.d/$1.start"
  chmod +x "/etc/local.d/$1.start"
  rc-update add local default >/dev/null 2>&1 || true
}

mkdir -p /opt/sjv/results
