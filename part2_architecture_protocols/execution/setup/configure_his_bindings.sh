#!/bin/sh
# Guest configuration only: match outbound sources to H-07 and H-06.
set -eu
[ "$(hostname)" = his-vm ] || exit 2
sed -i 's/^server=1\.1\.1\.1$/server=1.1.1.1@192.168.10.53/' /etc/dnsmasq.d/sjv.conf
grep -q '^bindacqaddress 192.168.10.57$' /etc/chrony/chrony.conf ||
    printf '\nbindacqaddress 192.168.10.57\n' >> /etc/chrony/chrony.conf
rc-service dnsmasq restart
rc-service chronyd restart
echo 'Configured DNS upstream source .53 and NTP upstream source .57.'
