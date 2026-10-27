#!/bin/sh
# his-vm: stands in for the HIS servers (report Section 11.4, step 3)
#   192.168.10.20 EMR DB (1433)   192.168.10.21 EMR app (443)
#   192.168.10.40 IF engine (2575) 192.168.10.53 DNS  192.168.10.57 NTP
# Copy this folder to /opt/sjv first:  scp -r lab root@192.168.10.20:/opt/sjv/
. "$(dirname "$0")/common.sh"
need_root
install_tools dnsmasq openssh-server

write_static 192.168.10.20/24 192.168.10.1 192.168.10.21/24 192.168.10.40/24 192.168.10.53/24 192.168.10.57/24
set_resolver 192.168.10.53

# DNS: answers lab names, forwards the rest (H-07 lets H_DNS recurse)
cat > /etc/dnsmasq.d/sjv.conf <<'CONF'
listen-address=192.168.10.53
bind-interfaces
no-resolv
server=1.1.1.1
log-queries
log-facility=/var/log/dnsmasq.log
address=/emr.sjv.local/192.168.10.21
address=/emrdb.sjv.local/192.168.10.20
address=/ifengine.sjv.local/192.168.10.40
address=/pacs.sjv.local/192.168.40.10
CONF
rc-update add dnsmasq default; rc-service dnsmasq restart

# NTP server for the lab zones (DV-02, R-01)
cat > /etc/chrony/chrony.conf <<'CONF'
pool pool.ntp.org iburst
bindaddress 192.168.10.57
allow 192.168.0.0/16
local stratum 8
CONF
rc-update add chronyd default; rc-service chronyd restart

# Fake application services, started at every boot
enable_local_start sjv-his <<'START'
#!/bin/sh
cd /opt/sjv/lab/services
nohup python3 emr_app.py --bind 192.168.10.21 --port 443 >> /var/log/sjv-emr.log 2>&1 &
nohup python3 mllp_server.py --bind 192.168.10.40 --port 2575 >> /var/log/sjv-mllp.log 2>&1 &
nohup python3 fake_mssql.py --bind 192.168.10.20 --port 1433 >> /var/log/sjv-mssql.log 2>&1 &
START
/etc/local.d/sjv-his.start
echo "[+] his-vm ready. Check: ss -ltnp | grep -E '443|2575|1433'"
