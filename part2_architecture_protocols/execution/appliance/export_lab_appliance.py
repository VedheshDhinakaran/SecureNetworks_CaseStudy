"""Export only this project's five installed VMs, with a separate private access bundle.

Dry run by default. --export adds a dedicated team key and unchanged Part IV
scripts, shuts down the guests cleanly, exports into ignored workspace storage,
verifies archive member hashes, and restarts guests that were originally running.
No installer images, personal SSH keys or private values enter public results.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile

EXECUTION = Path(__file__).resolve().parents[1]
ROOT = EXECUTION.parents[1]
NAMES = ("opnsense", "his-vm", "pump-vm", "rad-vm", "vendor-vm")
HOSTS = dict(zip(NAMES, ("192.168.90.1", "192.168.10.20", "192.168.30.10", "192.168.40.100", "10.61.0.50")))
RESERVE = 512 * 1024 * 1024


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_appliance(ova: Path, access_zip: Path, vbox: Path, run) -> None:
    """Verify an existing archive without exporting or modifying any VM."""
    output = ova.parent
    print("Verifying every OVF/VMDK manifest digest", flush=True)
    with tarfile.open(ova, "r:") as archive_file:
        members = archive_file.getmembers()
        ovf_member = next(member for member in members if member.name.endswith(".ovf"))
        manifest_member = next(member for member in members if member.name.endswith(".mf"))
        manifest = archive_file.extractfile(manifest_member).read().decode()
        ovf = archive_file.extractfile(ovf_member).read()
        systems = ET.fromstring(ovf).findall(".//{*}VirtualSystem")
        if len(systems) != 5 or len([m for m in members if m.name.endswith(".vmdk")]) != 5:
            raise RuntimeError("Expected five virtual systems and five virtual disks in the appliance")
        networks = {}
        expected_zone_networks = {"his-vm": "sjv-his", "pump-vm": "sjv-devices",
                                  "rad-vm": "sjv-radiology", "vendor-vm": "sjv-vendor"}
        for system in systems:
            name = next(value for key, value in system.attrib.items() if key.rsplit("}", 1)[-1] == "id")
            adapters = []
            for adapter in system.findall(".//{*}Adapter"):
                if adapter.get("enabled") != "true":
                    continue
                active = [child for child in adapter if child.tag.rsplit("}", 1)[-1] != "DisabledModes"]
                if len(active) != 1:
                    raise RuntimeError("Unexpected exported adapter attachment: " + name)
                adapters.append({"slot": int(adapter.get("slot")),
                                 "attachment": active[0].tag.rsplit("}", 1)[-1],
                                 "network": active[0].get("name"), "mac": adapter.get("MACAddress")})
            networks[name] = sorted(adapters, key=lambda item: item["slot"])
        if set(networks) != set(NAMES):
            raise RuntimeError("Exported virtual-system names do not match the lab")
        expected_firewall = ["NAT", "HostOnlyInterface"] + ["InternalNetwork"] * 4
        if [item["attachment"] for item in networks["opnsense"]] != expected_firewall:
            raise RuntimeError("The exported firewall must retain all six original NICs")
        if [item["network"] for item in networks["opnsense"]][2:] != list(expected_zone_networks.values()):
            raise RuntimeError("Exported firewall internal-network names differ from the lab")
        for name, expected_network in expected_zone_networks.items():
            if len(networks[name]) != 1 or networks[name][0]["network"] != expected_network:
                raise RuntimeError("Exported zone network differs from the lab: " + name)
        verified = []
        for algorithm, member_name, expected in re.findall(r"(SHA1|SHA256)\s*\((.+?)\)\s*=\s*([a-fA-F0-9]+)", manifest):
            digest = hashlib.new(algorithm.lower())
            stream = archive_file.extractfile(member_name)
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            if digest.hexdigest().lower() != expected.lower():
                raise RuntimeError("Archive manifest checksum failed: " + member_name)
            verified.append(member_name)
            print("Manifest digest verified: " + member_name, flush=True)
        if len(verified) != 6:
            raise RuntimeError("Expected checksum verification for the OVF plus five disks")
    with zipfile.ZipFile(access_zip) as private_bundle:
        if private_bundle.testzip() is not None or not all(name.startswith(".local/") and ".." not in Path(name).parts
                                                          for name in private_bundle.namelist()):
            raise RuntimeError("Private bundle integrity or ignored extraction path check failed")
    dry_run = run([vbox, "import", ova, "--dry-run"], timeout=180)
    (output / "import_dry_run.txt").write_text(dry_run, encoding="utf-8")
    digest = file_hash(ova)
    (output / "CS07_Hospital_Lab.ova.sha256").write_text(digest + "  " + ova.name + "\n", encoding="ascii")
    preparation = json.loads((output / "pre_export_checks.json").read_text())
    export_record = {
        "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "appliance": ova.relative_to(ROOT).as_posix(), "appliance_bytes": ova.stat().st_size,
        "appliance_sha256": digest, "access_bundle": access_zip.relative_to(ROOT).as_posix(),
        "access_bundle_bytes": access_zip.stat().st_size, "access_bundle_sha256": file_hash(access_zip),
        "virtualbox_version": run([vbox, "--version"]).strip(),
        "vm_names": list(NAMES), "virtual_system_count": len(systems), "disk_count": 5,
        "manifest_members_verified": verified, "virtualbox_import_dry_run_passed": True,
        "exported_network_adapters": networks,
        **preparation,
        "recipient_boot_and_readiness": "Must be verified on the recipient's hardware after import",
    }
    (EXECUTION / "results/appliance_export.json").write_text(json.dumps(export_record, indent=2) + "\n", encoding="utf-8")
    print(f"Verified appliance: {ova.stat().st_size / 1024**3:.2f} GiB", flush=True)
    print("Private access ZIP verified; no credential values printed", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--verify-existing", action="store_true", help="Finish archive verification only; no guest changes")
    parser.add_argument("--verify-source-access", action="store_true", help="Check dedicated team SSH after source guests restart")
    parser.add_argument("--vm-root", type=Path, default=Path.home() / "VirtualBox VMs/CS07")
    args = parser.parse_args()
    vbox = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Oracle/VirtualBox/VBoxManage.exe"
    native = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32/OpenSSH"

    def run(command, timeout=60, private=False):
        result = subprocess.run([str(value) for value in command], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if result.returncode:
            detail = "Private command output withheld" if private else (result.stdout + result.stderr)[-1800:]
            raise RuntimeError("Command failed: " + str(command[0]) + ": " + detail)
        return result.stdout

    def info(name):
        result = {}
        for line in run([vbox, "showvminfo", name, "--machinereadable"]).splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            try:
                result[key] = ast.literal_eval(value) if value.startswith('"') else value
            except (ValueError, SyntaxError):
                result[key] = value
        expected = (args.vm_root / name / (name + ".vbox")).resolve()
        if Path(result["CfgFile"]).resolve() != expected:
            raise RuntimeError("VM is outside the requested CS07 directory: " + name)
        return result

    output = EXECUTION / ".local/appliance"
    ova = output / "CS07_Hospital_Lab.ova"
    access_zip = output / "CS07_Lab_Access_PRIVATE.zip"
    if args.verify_existing:
        verify_appliance(ova, access_zip, vbox, run)
        return
    initial = {name: info(name) for name in NAMES}
    if args.verify_source_access:
        team_key = output / "private_access_stage/.local/ssh/lab_admin"
        for name in NAMES:
            deadline = time.monotonic() + 240
            while True:
                result = subprocess.run([str(native / "ssh.exe"), "-i", str(team_key), "-o", "BatchMode=yes",
                                         "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
                                         "-o", "UserKnownHostsFile=" + str(team_key.parent / "known_hosts"),
                                         "root@" + HOSTS[name], "echo CS07_TEAM_KEY_OK"],
                                        capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and "CS07_TEAM_KEY_OK" in result.stdout:
                    print(name + ": dedicated team SSH works after reboot", flush=True)
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Post-export team SSH did not become ready: " + name)
                print("Waiting for source guest boot: " + name, flush=True)
                time.sleep(3)
        record_path = EXECUTION / "results/appliance_export.json"
        record = json.loads(record_path.read_text())
        record["source_post_export_team_ssh_verified"] = True
        record["source_post_export_team_ssh_verified_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return
    if any(value["VMState"] not in ("running", "poweroff") for value in initial.values()):
        raise RuntimeError("Each lab guest must be running or cleanly powered off, not saved/paused")
    if ova.exists() or access_zip.exists():
        raise RuntimeError("An appliance/access bundle already exists; refusing to overwrite it")
    free = shutil.disk_usage(EXECUTION).free
    print(f"Workspace free: {free / 1024**3:.2f} GiB; export stops below a 512 MiB reserve", flush=True)
    print("Output: " + str(ova), flush=True)
    print("Five VMs: " + ", ".join(NAMES), flush=True)
    if not args.export:
        print("Plan only. Pass --export to prepare, shut down, export and restore the running lab.")
        return
    if free < 2 * 1024**3:
        raise RuntimeError("Not enough workspace space for the estimated compressed appliance plus reserve")
    output.mkdir(parents=True, exist_ok=True)
    staging = output / "private_access_stage"
    ssh_stage = staging / ".local/ssh"
    ssh_stage.mkdir(parents=True, exist_ok=True)
    handoff_key = ssh_stage / "lab_admin"
    if not handoff_key.exists():
        run([native / "ssh-keygen.exe", "-q", "-t", "ed25519", "-N", "", "-C", "cs07-team-handoff", "-f", handoff_key], private=True)
    public_key = handoff_key.with_suffix(".pub").read_text().strip()
    original_key = EXECUTION / ".local/ssh/lab_admin"
    options = ["-i", str(original_key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + str(EXECUTION / ".local/ssh/known_hosts")]

    def ssh(name, command, timeout=60, private=False, team_key=False):
        selected = list(options)
        if team_key:
            selected[1] = str(handoff_key)
        return run([native / "ssh.exe", *selected, "root@" + HOSTS[name], command], timeout, private)

    def upload(name, path):
        run([native / "scp.exe", "-O", *options, path, "root@" + HOSTS[name] + ":/tmp/"], timeout=90)

    # Preserve the existing Part III policy; add no temporary setup access.
    sys.path.insert(0, str(EXECUTION))
    import urllib3
    from run_firewall_loader import interface_rules, original
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    credentials = dict(line.split("=", 1) for line in (EXECUTION / ".local/api/apikey.txt").read_text().splitlines() if "=" in line)
    firewall = original.OPNsense(HOSTS["opnsense"], credentials["key"], credentials["secret"], False)
    rules = interface_rules(firewall)
    if len(rules) != 18 or any("SETUP-TEMP" in row["description"] for row in rules):
        raise RuntimeError("Export requires exactly 18 intended rules and no temporary setup rules")
    for name in NAMES:
        if initial[name]["VMState"] == "poweroff":
            run([vbox, "startvm", name, "--type", "headless"])
    # Reaching each installed SSH service is stronger than a fixed boot delay.
    for name in NAMES:
        deadline = time.monotonic() + 240
        while True:
            try:
                ssh(name, "true", timeout=15)
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Installed guest did not become reachable: " + name)
                time.sleep(3)

    public_file = output / "cs07_handoff.pub"
    public_file.write_text(public_key + "\n", encoding="ascii")
    firewall_script = output / "cs07_handoff_key.php"
    firewall_script.write_text("""<?php
require_once 'config.inc';
require_once 'system.inc';
require_once 'util.inc';
if (PHP_OS_FAMILY !== 'BSD') { throw new RuntimeException('OPNsense only'); }
$key = trim(file_get_contents('/tmp/cs07_handoff.pub'));
if (!preg_match('/^ssh-ed25519 [A-Za-z0-9+\\/=]+ cs07-team-handoff$/', $key)) {
    throw new RuntimeException('Unexpected handoff public key');
}
$path = '/root/.ssh/authorized_keys';
$keys = trim(file_get_contents($path));
foreach ($config['system']['user'] as &$user) {
    if (($user['name'] ?? '') === 'root') {
        $persisted = trim(base64_decode($user['authorizedkeys'] ?? ''));
        $lines = array_unique(array_filter(array_merge(explode("\\n", $keys), explode("\\n", $persisted), [$key])));
        $keys = implode("\\n", $lines) . "\\n";
        $user['authorizedkeys'] = base64_encode($keys);
    }
}
unset($user);
write_config('CS07 team appliance handoff public SSH key');
file_put_contents($path, $keys);
chmod($path, 0600);
echo "Dedicated team public key persisted; firewall policy unchanged.\\n";
""", encoding="utf-8")
    upload("opnsense", public_file)
    upload("opnsense", firewall_script)
    ssh("opnsense", "php /tmp/cs07_handoff_key.php")

    # Stage the original Part IV tree, normalising CRLF only in deployed shell copies.
    archive = output / "part4_original_scripts.tar.gz"
    tracked = run(["git", "-C", ROOT, "ls-files", "part4_lab_monitoring_response"]).splitlines()
    with tarfile.open(archive, "w:gz") as tar:
        for relative in tracked:
            source = ROOT / relative
            if not source.is_file():
                continue
            data = source.read_bytes()
            if source.suffix == ".sh":
                data = data.replace(b"\r\n", b"\n")
            member = tarfile.TarInfo(relative)
            member.size = len(data)
            member.mode = 0o755 if source.suffix == ".sh" else 0o644
            tar.addfile(member, io.BytesIO(data))
    console_passwords = {}
    for name in NAMES[1:]:
        upload(name, public_file)
        ssh(name, "mkdir -p /root/.ssh; chmod 700 /root/.ssh; touch /root/.ssh/authorized_keys; "
                  "grep -qF -f /tmp/cs07_handoff.pub /root/.ssh/authorized_keys || cat /tmp/cs07_handoff.pub >> /root/.ssh/authorized_keys; "
                  "chmod 600 /root/.ssh/authorized_keys")
        upload(name, archive)
        ssh(name, "mkdir -p /opt/sjv; tar -xzf /tmp/part4_original_scripts.tar.gz -C /opt/sjv; sync")
        console_passwords[name] = ssh(name, "cat /root/.cs07-console-password", private=True).strip()
        print(name + ": team SSH key and original experiment scripts prepared", flush=True)
    for name in NAMES:
        ssh(name, "true", team_key=True)
    print("Dedicated team SSH authentication verified on all five installed VMs", flush=True)
    preparation = {
        "source_vm_directory": str(args.vm_root),
        "source_git_commit": run(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip(),
        "policy_rule_count": len(rules), "temporary_setup_rules": 0,
        "dedicated_team_ssh_key_verified_on_five_guests": True,
        "original_part4_files_staged": len(tracked), "shell_copy_change": "CRLF to LF only",
        "source_readiness": "readiness_20261027T222816", "source_readiness_checks": 35,
        "originally_running": [name for name in NAMES if initial[name]["VMState"] == "running"],
    }
    (output / "pre_export_checks.json").write_text(json.dumps(preparation, indent=2) + "\n", encoding="utf-8")

    api_dest = staging / ".local/api/apikey.txt"
    api_dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(EXECUTION / ".local/api/apikey.txt", api_dest)
    runtime_dest = staging / ".local/bootstrap/runtime_lab_rules.yaml"
    runtime_dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(EXECUTION / ".local/bootstrap/runtime_lab_rules.yaml", runtime_dest)
    private_readme = [
        "PRIVATE CS07 LAB ACCESS - share only with your project team; never commit this bundle.",
        "Extract this ZIP into part2_architecture_protocols/execution in your repository.",
        "The .local/ directory is intentionally ignored by Git.",
        "OPNsense GUI: https://192.168.90.1 | user: root | lab password: opnsense",
        "SSH: root; dedicated team key: .local/ssh/lab_admin (no passphrase).",
        "Firewall API credentials: .local/api/apikey.txt.",
        "These credentials apply only to the isolated teaching lab.",
        "Alpine console root passwords (SSH uses the bundled key):",
    ]
    private_readme.extend(name + ": " + value for name, value in console_passwords.items())
    private_note = staging / ".local/appliance/ACCESS_README_PRIVATE.txt"
    private_note.parent.mkdir(parents=True, exist_ok=True)
    private_note.write_text("\n".join(private_readme) + "\n", encoding="utf-8")
    with zipfile.ZipFile(access_zip, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(staging).as_posix())

    originally_running = [name for name in NAMES if initial[name]["VMState"] == "running"]
    shutdown_requested = []
    try:
        # All access/staging must finish before the first guest is shut down.
        for name in (*NAMES[1:], NAMES[0]):
            command = "nohup sh -c 'sleep 2; /sbin/poweroff' >/dev/null 2>&1 </dev/null &" if name != "opnsense" else "/usr/sbin/daemon -f /bin/sh -c 'sleep 2; /sbin/shutdown -p now'"
            ssh(name, command)
            shutdown_requested.append(name)
            print("Clean shutdown requested: " + name, flush=True)
        deadline = time.monotonic() + 240
        while True:
            states = {name: info(name)["VMState"] for name in NAMES}
            if all(state == "poweroff" for state in states.values()):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Guests did not shut down cleanly; refusing forced power-off: " + str(states))
            time.sleep(3)
        print("All five guests are cleanly powered off; exporting compressed disks", flush=True)
        log_file = output / "export_console.log"
        with log_file.open("w", encoding="utf-8") as log:
            process = subprocess.Popen([str(vbox), "export", *NAMES, "--output=" + str(ova), "--ovf20", "--options=manifest"],
                                       stdout=log, stderr=subprocess.STDOUT)
            last_message = 0.0
            while process.poll() is None:
                remaining = shutil.disk_usage(output).free
                if remaining < RESERVE:
                    process.terminate()
                    process.wait(timeout=30)
                    raise RuntimeError("Export stopped to preserve 512 MiB free; partial ignored archive retained")
                if time.monotonic() - last_message > 25:
                    size = ova.stat().st_size if ova.exists() else 0
                    print(f"Export in progress: archive {size / 1024**2:.0f} MiB; free {remaining / 1024**3:.2f} GiB", flush=True)
                    last_message = time.monotonic()
                time.sleep(2)
        if process.returncode:
            raise RuntimeError("VirtualBox export failed; see ignored export_console.log")
        print("Export finished", flush=True)
        verify_appliance(ova, access_zip, vbox, run)
    finally:
        for name in originally_running:
            if name in shutdown_requested and info(name)["VMState"] == "poweroff":
                run([vbox, "startvm", name, "--type", "headless"])
                print("Restarted original VM: " + name, flush=True)


if __name__ == "__main__":
    main()
