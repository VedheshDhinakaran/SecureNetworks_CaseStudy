#!/bin/sh
# vendor-vm: a vendor engineer's laptop on vendor Wi-Fi (DHCP from 10.61.0.50-99)
. "$(dirname "$0")/common.sh"
need_root
install_tools openssh-server
write_dhcp
echo "[+] vendor-vm ready. Address: $(ip -4 -o addr show eth0 | awk '{print $4}')"
