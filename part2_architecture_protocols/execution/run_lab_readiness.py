"""Run actual Part II readiness checks with setup mode off and bounded PF logs."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib3
import requests
from lab_ssh import HOSTS
from run_firewall_loader import interface_rules, original

HERE = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("Pass --run only after all four guests are configured and setup mode is off")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    credentials = dict(line.split("=", 1) for line in (HERE / ".local/api/apikey.txt").read_text().splitlines() if "=" in line)
    firewall = original.OPNsense(HOSTS["opnsense"], credentials["key"], credentials["secret"], False)
    # A disk reboot can take several minutes on the Windows Hyper-V backend.
    # Wait for the actual API rather than counting an unavailable guest as
    # a failed policy test. Requests and progress intervals stay bounded.
    deadline = time.monotonic() + 180
    announced = False
    while True:
        try:
            response = firewall.s.post("https://" + HOSTS["opnsense"] + "/api/firewall/filter/searchRule?interface=lan",
                                       json={"current": 1, "rowCount": 1}, timeout=3)
            response.raise_for_status()
            if "rows" not in response.json():
                raise RuntimeError("Unexpected firewall API response")
            break
        except requests.RequestException:
            if time.monotonic() >= deadline:
                raise RuntimeError("Firewall API did not become ready within three minutes")
            if not announced:
                print("Waiting for the installed firewall to finish booting...", flush=True)
                announced = True
            time.sleep(2)
    rules = interface_rules(firewall)
    assert len(rules) == 18 and not any("SETUP-TEMP" in row["description"] for row in rules), "Readiness requires exactly 18 rules and zero temporary setup rules"
    assert len({row["description"] for row in rules}) == 18, "Duplicate policy rules remain"
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=5, minutes=30))).strftime("%Y%m%dT%H%M%S")
    directory = HERE / "results" / ("readiness_" + stamp)
    directory.mkdir(parents=True)
    (directory / "firewall_rules.json").write_text(json.dumps(rules, indent=2) + "\n", encoding="utf-8")
    native = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32/OpenSSH"
    options = ["-i", str(HERE / ".local/ssh/lab_admin"), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + str(HERE / ".local/ssh/known_hosts")]

    def run(command, timeout=45):
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)

    def ssh(role, command, timeout=45):
        return run([str(native / "ssh.exe"), *options, "root@" + HOSTS[role], command], timeout)

    def save(name, result):
        (directory / name).write_text("Exit code: " + str(result.returncode) + "\n" + result.stdout + result.stderr, encoding="utf-8")

    state = ssh("opnsense", "pfctl -si; pfctl -sr")
    save("firewall_active.txt", state)
    assert "Status: Enabled" in state.stdout, "PF is not enabled"
    cleared = ssh("opnsense", "pfctl -k 192.168.10.0/24; pfctl -k 192.168.30.0/24; pfctl -k 192.168.40.0/24; pfctl -k 10.61.0.0/24")
    save("temporary_zone_states_cleared.txt", cleared)
    started = ssh("opnsense", "pkill -F /tmp/cs07-readiness.pid; /usr/sbin/daemon -f -p /tmp/cs07-readiness.pid -o /tmp/cs07-readiness-capture.log /usr/sbin/tcpdump -U -n -i pflog0 -s 256 -c 200 -w /tmp/cs07-readiness.pcap")
    save("capture_started.txt", started)
    roles = []
    try:
        result = run([sys.executable, "-B", str(HERE / "verify_lab_readiness.py"), "bastion", "--plan",
                      str(HERE / "results/lab_network_plan.json"), "--output", str(directory / "bastion.json")])
        save("bastion.txt", result)
        roles.append(json.loads((directory / "bastion.json").read_text()))
        print("bastion: " + ("PASS" if roles[-1]["passed"] else "FAIL"), flush=True)
        for role in ["his-vm", "pump-vm", "rad-vm", "vendor-vm"]:
            upload = run([str(native / "scp.exe"), "-O", *options, str(HERE / "verify_lab_readiness.py"),
                          str(HERE / "results/lab_network_plan.json"), "root@" + HOSTS[role] + ":/tmp/"])
            assert upload.returncode == 0, role + " readiness upload failed: " + upload.stderr
            result = ssh(role, "python3 -B /tmp/verify_lab_readiness.py " + role
                         + " --plan /tmp/lab_network_plan.json --output /tmp/cs07-readiness.json")
            save(role + ".txt", result)
            downloaded = ssh(role, "cat /tmp/cs07-readiness.json")
            record = json.loads(downloaded.stdout)
            (directory / (role + ".json")).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            roles.append(record)
            print(role + ": " + ("PASS" if record["passed"] else "FAIL"), flush=True)
    finally:
        ssh("opnsense", "pkill -F /tmp/cs07-readiness.pid")
    time.sleep(0.5)
    decoded = ssh("opnsense", "/usr/sbin/tcpdump -nn -e -tttt -r /tmp/cs07-readiness.pcap")
    save("firewall_packet_log.txt", decoded)
    copied = run([str(native / "scp.exe"), "-O", *options, "root@" + HOSTS["opnsense"] + ":/tmp/cs07-readiness.pcap", str(directory / "firewall.pcap")])
    assert copied.returncode == 0, "Packet capture download failed"
    correlation = []
    for role in roles:
        for item in role["checks"]:
            observed = item.get("observed")
            if not isinstance(observed, dict) or not observed.get("expected_block"):
                continue
            pattern = (r"block .*" + re.escape(observed["source"]) + r"\.\d+ > "
                       + re.escape(observed["destination"]) + r"\." + str(observed["port"]) + r"\b")
            matched = [line for line in decoded.stdout.splitlines() if re.search(pattern, line)]
            correlation.append({"role": role["role"], "check": item["name"], "passed": bool(matched), "log_lines": matched})
    summary = {"recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(), "scope": "Part II readiness; E1-E8 remain separate",
               "policy_rule_count": len(rules), "temporary_setup_rule_count": 0,
               "roles": [{"role": role["role"], "passed": role["passed"], "checks": len(role["checks"])} for role in roles],
               "check_count": sum(len(role["checks"]) for role in roles), "blocked_flow_log_correlations": correlation,
               "passed": len(roles) == 5 and all(role["passed"] for role in roles) and len(correlation) == 7
                         and all(item["passed"] for item in correlation)}
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("Readiness: " + str(summary["check_count"]) + " checks; " + str(len(correlation)) + " blocked-flow log correlations", flush=True)
    print("Result: " + ("PASS" if summary["passed"] else "FAIL") + "; evidence " + str(directory), flush=True)
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
