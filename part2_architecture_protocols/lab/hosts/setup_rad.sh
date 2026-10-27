#!/bin/sh
# rad-vm: a radiology reading workstation (192.168.40.100) plus the
# PACS broker address (192.168.40.12) as an alias, so R-02 can be tested.
. "$(dirname "$0")/common.sh"
need_root
install_tools openssh-server
write_static 192.168.40.100/24 192.168.40.1 192.168.40.12/24
set_resolver 192.168.10.53
echo "[+] rad-vm ready. For experiment E4 start a listener when asked: nc -lk -p 8080"
