#!/bin/sh
# Run the README's original host script, retaining its output through a
# networking restart. This wrapper changes no policy or repository source.
set -eu
name="$(hostname)"
case "$name" in
    his-vm) script=setup_his.sh;;
    pump-vm) script=setup_pump.sh;;
    rad-vm) script=setup_rad.sh;;
    vendor-vm) script=setup_vendor.sh;;
    *) echo 'Unexpected guest hostname'; exit 2;;
esac
gateway="$(ip route | awk '/^default/ {print $3; exit}')"
mkdir -p /opt/sjv/results
wget -T 30 -O /tmp/original_lab.tar.gz "http://$gateway:8081/original_lab.tar.gz"
tar -xzf /tmp/original_lab.tar.gz -C /opt/sjv
printf 'pending\n' > /opt/sjv/results/zone_setup.exit
# Use the firewall resolver while installing packages; each original host
# script writes its final design resolver after package installation.
printf 'nameserver %s\n' "$gateway" > /etc/resolv.conf
saved_repositories=/tmp/cs07-zone-original.repositories
if wget -q -T 5 -O /dev/null "http://$gateway:8081/apk/main/x86_64/APKINDEX.tar.gz"; then
    cp /etc/apk/repositories "$saved_repositories"
    printf 'http://%s:8081/apk/main\nhttp://%s:8081/apk/community\n' "$gateway" "$gateway" > /etc/apk/repositories
fi
if [ "$name" = his-vm ]; then
    # Networking restart otherwise asynchronously restarts these dependent
    # services, racing the original script's explicit restart commands.
    for service in dnsmasq chronyd; do
        if rc-service --exists "$service"; then rc-service "$service" stop || true; fi
    done
fi
set +e
sh "/opt/sjv/lab/hosts/$script"
status=$?
set -e
if [ -f "$saved_repositories" ]; then cp "$saved_repositories" /etc/apk/repositories; fi
printf '%s\n' "$status" > /opt/sjv/results/zone_setup.exit
echo "CS07_ZONE_SETUP_EXIT $name $status"
exit "$status"
