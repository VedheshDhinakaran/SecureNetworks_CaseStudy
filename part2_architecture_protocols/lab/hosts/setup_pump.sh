#!/bin/sh
# pump-vm: a networked infusion pump in Z_DEVICES (192.168.30.10)
. "$(dirname "$0")/common.sh"
need_root
install_tools openssh-server
write_static 192.168.30.10/24 192.168.30.1
set_resolver 192.168.10.53
# A real pump sends observations to the interface engine every few
# minutes. This mimics that so DV-03 shows steady hits in the counters.
enable_local_start sjv-pump <<'START'
#!/bin/sh
cd /opt/sjv/lab/services
nohup sh -c 'while true; do python3 mllp_client.py --host 192.168.10.40 --device PUMP-030-010 >> /var/log/sjv-pump.log 2>&1; sleep 120; done' &
START
echo "[+] pump-vm ready. Start the periodic HL7 sender with: /etc/local.d/sjv-pump.start"
