#!/bin/sh
# Recover this lab's interrupted Alpine installation without repartitioning.
set -eu
[ "$(hostname)" = rad-vm ] || { echo 'Only the interrupted radiology guest'; exit 2; }
[ "$(cat /sys/class/dmi/id/product_name)" = VirtualBox ] || exit 2
[ "$(cat /sys/block/sda/size)" = 4194304 ] || exit 2
[ "$(awk '$2 == "/mnt" {print $1}' /proc/mounts)" = /dev/sda3 ] || {
    echo 'Expected the incomplete root filesystem mounted on /mnt'; exit 2;
}
# A failed setup-timezone download left this installer-only virtual
# dependency in the live package world. It cannot be fetched into /mnt.
if apk info -e .setup-timezone >/dev/null 2>&1; then apk del .setup-timezone; fi
cache=http://192.168.40.1:8081/apk
wget -q -T 5 -O /dev/null "$cache/main/x86_64/APKINDEX.tar.gz"
grep -v '^/media/' /etc/apk/repositories | awk '!seen[$0]++' > /tmp/cs07-original.repositories
printf '%s/main\n%s/community\n' "$cache" "$cache" > /etc/apk/repositories
cp /etc/apk/repositories /mnt/etc/apk/repositories
if [ ! -s /mnt/boot/vmlinuz-virt ] && [ -f /tmp/linux-virt-6.6.142-r0.apk ]; then
    if apk --root /mnt info -e linux-virt >/dev/null 2>&1; then apk --root /mnt del linux-virt; fi
    # Normal Alpine signature verification remains enabled.
    apk --root /mnt add /tmp/linux-virt-6.6.142-r0.apk
fi
setup-disk -m sys -k virt /mnt
mountpoint -q /mnt || mount /dev/sda3 /mnt
cp /tmp/cs07-original.repositories /etc/apk/repositories
cp /tmp/cs07-original.repositories /mnt/etc/apk/repositories
password="$(head -c 24 /dev/urandom | base64)"
printf 'root:%s\n' "$password" | chpasswd
umask 077
printf '%s\n' "$password" > /root/.cs07-console-password
unset password
cp /etc/shadow /mnt/etc/shadow
cp /root/.cs07-console-password /mnt/root/.cs07-console-password
dd if=/usr/share/syslinux/mbr.bin of=/dev/sda bs=440 count=1 conv=notrunc
sync
echo 'CS07_ALPINE_INSTALLED rad-vm; disk installation recovery completed.'
