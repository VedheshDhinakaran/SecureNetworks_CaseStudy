"""Bounded readiness probes for the existing lab; not the shared E1-E8 results.

Run only after setup mode is removed. Addresses come from the exported
original model and host scripts. Synthetic traffic only; no SQL or exploits.
"""
from __future__ import annotations
import argparse
import datetime as dt
import http.client
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import time


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["bastion", "his-vm", "pump-vm", "rad-vm", "vendor-vm"])
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    hosts = plan["hosts"]
    checks = []

    def check(name, operation):
        started = time.monotonic()
        try:
            detail = operation()
            result = {"name": name, "passed": True, "observed": detail}
        except Exception as error:
            result = {"name": name, "passed": False, "observed": type(error).__name__ + ": " + str(error)}
        result["seconds"] = round(time.monotonic() - started, 3)
        checks.append(result)
        print(("PASS " if result["passed"] else "FAIL ") + name + ": " + str(result["observed"]), flush=True)

    def tcp(address, port, blocked=False, source=None):
        connection = socket.socket()
        connection.settimeout(2)
        if source:
            connection.bind((source, 0))
        try:
            connection.connect((address, port))
            observed = {"source": connection.getsockname()[0], "destination": address, "port": port,
                        "result": "connected"}
        except TimeoutError:
            if blocked:
                return {"source": connection.getsockname()[0], "destination": address, "port": port,
                        "expected_block": True, "result": "connection timed out; correlate with firewall log"}
            raise
        finally:
            connection.close()
        if blocked:
            raise AssertionError("Prohibited connection succeeded: " + str(observed))
        return observed

    def web():
        connection = http.client.HTTPConnection(hosts["H_EMR_APP"], 443, timeout=3)
        try:
            connection.request("GET", "/health", headers={"User-Agent": "CS07-Part2-readiness"})
            response = connection.getresponse()
            body = response.read()
            assert response.status == 200 and b"ok" in body
            return {"status": response.status, "transport": "intentional plain HTTP on lab port 443"}
        finally:
            connection.close()

    def dns(server, use_tcp=False, name="emr.sjv.local", expected=None):
        identifier = int(time.time_ns() % 65536)
        question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0\0\1\0\1"
        message = struct.pack("!6H", identifier, 0x100, 1, 0, 0, 0) + question
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if use_tcp else socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            connection.connect((server, 53))
            if use_tcp:
                connection.sendall(struct.pack("!H", len(message)) + message)
                size = struct.unpack("!H", connection.recv(2))[0]
                response = b""
                while len(response) < size:
                    block = connection.recv(size - len(response))
                    if not block:
                        raise AssertionError("Incomplete TCP DNS response")
                    response += block
            else:
                connection.send(message)
                response = connection.recv(4096)
            response_id, flags, _, answers, _, _ = struct.unpack("!6H", response[:12])
            assert response_id == identifier and flags & 15 == 0 and answers > 0
            if expected:
                assert socket.inet_aton(expected) in response
            return {"server": server, "transport": "TCP" if use_tcp else "UDP", "answers": answers, "name": name}

    def internet_web(tls):
        kind = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        connection = kind("dl-cdn.alpinelinux.org", 443 if tls else 80, timeout=5)
        try:
            connection.request("HEAD", "/alpine/v3.20/main/x86_64/APKINDEX.tar.gz")
            response = connection.getresponse()
            assert 200 <= response.status < 400, response.status
            return {"host": "dl-cdn.alpinelinux.org", "port": 443 if tls else 80, "status": response.status}
        finally:
            connection.close()

    def ntp():
        message = bytearray(48)
        message[0] = 0x23
        now = time.time() + 2208988800
        message[40:48] = struct.pack("!II", int(now), int((now % 1) * 2**32))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            connection.sendto(message, (hosts["H_NTP"], 123))
            response, peer = connection.recvfrom(512)
        assert len(response) >= 48 and response[0] & 7 == 4
        assert response[24:32] == message[40:48] and 1 <= response[1] <= 15
        return {"server": peer[0], "stratum": response[1], "leap": response[0] >> 6,
                "scope": "NTP service response; external synchronization and NTS are separate"}

    def hl7(source=None):
        command = [sys.executable, "/opt/sjv/lab/services/mllp_client.py", "--host", hosts["H_IFENGINE"],
                   "--timeout", "3", "--device", "PART2-READINESS"]
        if source:
            command += ["--source", source]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0 and "-> AA" in result.stdout, result.stdout + result.stderr
        return result.stdout.strip()

    def inventory():
        assert socket.gethostname().split(".")[0] == args.role
        mounts = Path("/proc/mounts").read_text().splitlines()
        root = next(line.split()[0] for line in mounts if line.split()[1] == "/")
        assert root == "/dev/sda3", "Guest has not booted its installed disk"
        assert ":8081" not in Path("/etc/apk/repositories").read_text(), "Temporary package repository was not restored"
        records = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show", "eth0"]))
        addresses = [item["local"] for record in records for item in record["addr_info"]]
        specification = plan["lab_hosts"][args.role]
        if "addresses" in specification:
            assert set(specification["addresses"]).issubset(addresses), addresses
        else:
            lower, upper = map(ipaddress.ip_address, specification["dhcp"])
            assert any(lower <= ipaddress.ip_address(value) <= upper for value in addresses)
        for tool in ["python3", "nmap", "tcpdump", "tshark", "curl", "dig"]:
            assert shutil.which(tool), "Missing lab tool: " + tool
        return {"root": root, "addresses": addresses, "alpine": Path("/etc/alpine-release").read_text().strip(),
                "kernel": subprocess.check_output(["uname", "-r"], text=True).strip()}

    if args.role == "bastion":
        check("MGMT reaches live DB listener (control for blocked tests)", lambda: tcp(hosts["H_EMR_DB"], 1433))
        check("MGMT reaches EMR service", web)
        for role, specification in plan["lab_hosts"].items():
            address = specification.get("addresses", specification.get("dhcp"))[0]
            check("MGMT SSH to " + role, lambda address=address: tcp(address, 22))
    else:
        check("Installed guest, planned addresses and lab tools", inventory)
        if args.role in ("his-vm", "pump-vm", "rad-vm"):
            check("Internal DNS over UDP", lambda: dns(hosts["H_DNS"], expected=hosts["H_EMR_APP"]))
            check("Internal DNS over TCP", lambda: dns(hosts["H_DNS"], True, expected=hosts["H_EMR_APP"]))
        if args.role in ("pump-vm", "rad-vm"):
            check("Internal NTP response", ntp)
        if args.role == "his-vm":
            check("EMR HTTP health", web)
            check("DB TCP listener", lambda: tcp(hosts["H_EMR_DB"], 1433))
            check("HL7 stand-in accepts observation and sends AA", hl7)
            check("HIS resolver forwards an external name", lambda: dns(hosts["H_DNS"], name="example.com"))
        if args.role == "pump-vm":
            check("Pump HL7 permitted", hl7)
            check("Pump EMR access blocked", lambda: tcp(hosts["H_EMR_APP"], 443, True))
            check("Pump DB access blocked", lambda: tcp(hosts["H_EMR_DB"], 1433, True))
            check("Pump public web egress blocked", lambda: tcp(socket.gethostbyname("dl-cdn.alpinelinux.org"), 443, True))
        if args.role == "rad-vm":
            check("Radiology EMR access permitted", web)
            check("Radiology DB access blocked", lambda: tcp(hosts["H_EMR_DB"], 1433, True))
            check("Broker HL7 permitted", lambda: hl7(hosts["H_PACS_BROKER"]))
            check("Reading workstation HL7 blocked", lambda: tcp(hosts["H_IFENGINE"], 2575, True))
        if args.role == "vendor-vm":
            check("Vendor uses firewall DNS", lambda: dns(plan["lab_hosts"][args.role]["gateway"], name="example.com"))
            check("Vendor EMR access blocked", lambda: tcp(hosts["H_EMR_APP"], 443, True))
            check("Vendor DB access blocked", lambda: tcp(hosts["H_EMR_DB"], 1433, True))
            check("Vendor public HTTP permitted", lambda: internet_web(False))
            check("Vendor public HTTPS permitted", lambda: internet_web(True))
    record = {"role": args.role, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": "Part II lab readiness; not E1-E8 completion", "checks": checks,
              "passed": all(item["passed"] for item in checks)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
