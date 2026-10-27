"""SSH/SCP for the five isolated README lab guests using an ignored local key.

The fixed lab addresses cannot be replaced with an external host. Use --log
only for commands whose output contains no passwords, API keys or config.xml.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
HOSTS = {"opnsense": "192.168.90.1", "his-vm": "192.168.10.20",
         "pump-vm": "192.168.30.10", "rad-vm": "192.168.40.100", "vendor-vm": "10.61.0.50"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vm", choices=HOSTS)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--command")
    operation.add_argument("--upload", type=Path, nargs="+")
    parser.add_argument("--destination", default="/tmp/")
    parser.add_argument("--log", help="Save non-secret output under results/guest_setup")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.log and not re.fullmatch(r"[A-Za-z0-9_-]+", args.log):
        parser.error("Use a simple log label")
    ssh_dir = HERE / ".local" / "ssh"
    key = ssh_dir / "lab_admin"
    if not key.is_file():
        parser.error("Generate the private lab key in .local/ssh/lab_admin first")
    options = ["-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
               "-o", "UserKnownHostsFile=" + str(ssh_dir / "known_hosts"), "-o", "ConnectTimeout=10"]
    native = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "OpenSSH"
    target = "root@" + HOSTS[args.vm]
    if args.command:
        command = [str(native / "ssh.exe"), *options, target, args.command]
    else:
        for path in args.upload:
            if not path.exists():
                parser.error("Missing upload: " + str(path))
        if not args.destination.startswith(("/tmp/", "/opt/sjv/", "/root/.ssh/")):
            parser.error("Upload destination must be in /tmp/, /opt/sjv/ or /root/.ssh/")
        command = [str(native / "scp.exe"), "-O", "-r", *options,
                   *(str(path) for path in args.upload), target + ":" + args.destination]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=args.timeout)
    output = result.stdout + result.stderr
    print(output, end="")
    if args.log:
        stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=5, minutes=30))).strftime("%Y%m%dT%H%M%S")
        directory = HERE / "results" / "guest_setup"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (args.vm + "_" + args.log + "_" + stamp + ".txt")).write_text(
            "VM: " + args.vm + "\nExit code: " + str(result.returncode) + "\n\n" + output,
            encoding="utf-8")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
