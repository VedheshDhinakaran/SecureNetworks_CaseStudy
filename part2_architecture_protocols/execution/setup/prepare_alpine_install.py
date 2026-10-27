"""Prepare local answer files for setup-alpine; original host scripts stay intact.

Only a public SSH key is included. Serve the generated bootstrap directory
temporarily from the isolated firewall while setup mode is enabled.
"""
from __future__ import annotations

import json
import hashlib
import io
from pathlib import Path
import tarfile
import shutil

HERE = Path(__file__).resolve().parents[1]
PART2 = HERE.parent


def main() -> None:
    plan = json.loads((HERE / "results" / "lab_network_plan.json").read_text())
    public_key = (HERE / ".local" / "ssh" / "lab_admin.pub").read_text().strip()
    if not public_key.startswith("ssh-ed25519 ") or "\n" in public_key:
        raise ValueError("Expected one public administration key")
    output = HERE / ".local" / "bootstrap" / "http"
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__).parent / "run_zone_setup.sh", output / "run_zone_setup.sh")
    hosts = {"his-vm": ("opt1", "192.168.10.20"), "pump-vm": ("opt2", "192.168.30.10"),
             "rad-vm": ("opt3", "192.168.40.100"), "vendor-vm": ("opt4", None)}
    for hostname, (interface, address) in hosts.items():
        data = plan["interfaces"][interface]
        network = ("iface eth0 inet dhcp\n" if address is None else
                   "iface eth0 inet static\n    address " + address + "/" + str(data["prefix"])
                   + "\n    gateway " + data["address"] + "\n")
        text = "\n".join([
            'KEYMAPOPTS="us us"', 'HOSTNAMEOPTS="' + hostname + '"', 'DEVDOPTS="mdev"',
            'INTERFACESOPTS="auto lo\niface lo inet loopback\n\nauto eth0\n' + network + '"',
            'DNSOPTS="' + data["address"] + '"', 'TIMEZONEOPTS="Asia/Kolkata"', 'PROXYOPTS="none"',
            'APKREPOSOPTS="-1 -c"', 'USEROPTS="none"', 'SSHDOPTS="openssh"',
            'ROOTSSHKEY="' + public_key + '"', 'NTPOPTS="chrony"',
            'DISKOPTS="-m sys -k virt -s 128 /dev/sda"', 'LBUOPTS="none"', 'APKCACHEOPTS="none"', ""])
        (output / (hostname + ".answers")).write_text(text, encoding="utf-8", newline="\n")
    line_endings = []
    with tarfile.open(output / "original_lab.tar.gz", "w:gz") as archive:
        for path in sorted((PART2 / "lab").rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            original = path.read_bytes()
            deployed = original.replace(b"\r\n", b"\n") if path.suffix == ".sh" else original
            info = archive.gettarinfo(str(path), arcname="lab/" + path.relative_to(PART2 / "lab").as_posix())
            info.size = len(deployed)
            if path.suffix == ".sh":
                info.mode = 0o755
            archive.addfile(info, io.BytesIO(deployed))
            if original != deployed:
                line_endings.append({"path": path.relative_to(PART2).as_posix(),
                    "source_sha256": hashlib.sha256(original).hexdigest(),
                    "guest_copy_sha256": hashlib.sha256(deployed).hexdigest()})
    (HERE / "results/guest_line_endings.json").write_text(json.dumps({
        "purpose": "Windows CRLF converted to Unix LF in deployed shell copies only; source contents otherwise unchanged",
        "repository_sources_modified": False, "files": line_endings}, indent=2) + "\n", encoding="utf-8")
    runner = r'''#!/bin/sh
set -eu
name="${1:?Specify his-vm, pump-vm, rad-vm or vendor-vm}"
case "$name" in his-vm|pump-vm|rad-vm|vendor-vm) ;; *) exit 2;; esac
[ "$(cat /sys/class/dmi/id/product_name)" = VirtualBox ] || { echo 'Not the VirtualBox lab'; exit 2; }
[ "$(cat /sys/block/sda/size)" = 4194304 ] || { echo 'Unexpected lab disk size'; exit 2; }
for partition in /sys/block/sda/sda[0-9]*; do
    [ ! -e "$partition" ] || { echo 'Disk already partitioned; refusing another install'; exit 2; }
done
gateway="$(ip route | awk '/^default/ { print $3; exit }')"
[ -n "$gateway" ] || { echo 'Configure the README zone address and gateway first'; exit 2; }
base="http://$gateway:8081"
wget -O /tmp/lab.answers "$base/$name.answers"
# Empty password is only an installer bootstrap. setup-sshd installs the
# public key; immediately give root a random password and keep it guest-local.
ERASE_DISKS=/dev/sda setup-alpine -e -f /tmp/lab.answers
password="$(head -c 24 /dev/urandom | base64)"
printf 'root:%s\n' "$password" | chpasswd
umask 077
printf '%s\n' "$password" > /root/.cs07-console-password
unset password
# setup-alpine has already installed the disk. Persist the final password
# and its private console recovery file into that installed system too.
mkdir -p /mnt/cs07-installed
mount /dev/sda3 /mnt/cs07-installed
cp /etc/shadow /mnt/cs07-installed/etc/shadow
cp /root/.cs07-console-password /mnt/cs07-installed/root/.cs07-console-password
umount /mnt/cs07-installed
echo "CS07_ALPINE_INSTALLED $name; shut down, detach the ISO, then boot the disk."
'''
    (output / "install_alpine.sh").write_text(runner, encoding="utf-8", newline="\n")
    print("Prepared four answer files, the installer wrapper and an archive of the unchanged lab/ folder")
    print("Local staging directory: " + str(output))


if __name__ == "__main__":
    main()
