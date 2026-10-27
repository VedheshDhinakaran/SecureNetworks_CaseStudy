"""Audit Git size, source preservation and private-file exclusions; optionally tidy debug evidence.

--tidy moves only this directory's generated debug output to ignored .local.
It never deletes data, stages files, commits or pushes.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tidy", action="store_true")
    args = parser.parse_args()
    moved = []
    if args.tidy:
        setup = HERE / "results/setup"
        setup.mkdir(parents=True, exist_ok=True)
        for role in ["his-vm", "pump-vm", "rad-vm", "vendor-vm"]:
            logs = sorted((HERE / "results/guest_setup").glob(role + "_completed_setup_*.txt"))
            if logs:
                shutil.copyfile(logs[-1], setup / (role + "_setup.txt"))
        keep = {"vendor-vm_vendor_dhcp", "opnsense_lab_ready"}
        debug = HERE / ".local/installation_debug"
        candidates = list((HERE / "results/vm_installation").glob("*.png"))
        candidates += list((HERE / "results/guest_setup").glob("*.txt"))
        candidates += [HERE / "results/firewall_api_audit.json"]
        for summary in (HERE / "results").glob("offline_*/summary.json"):
            record = json.loads(summary.read_text())
            if any(check["exit_code"] for check in record["checks"]):
                candidates += [path for path in summary.parent.iterdir() if path.is_file()]
        for source in candidates:
            if not source.is_file() or any(source.name.startswith(prefix) for prefix in keep):
                continue
            target = debug / source.relative_to(HERE / "results")
            assert source.resolve().is_relative_to(HERE / "results")
            assert target.resolve().is_relative_to(HERE / ".local")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                continue
            shutil.move(str(source), str(target))
            moved.append(source.relative_to(HERE).as_posix())
    baseline = json.loads((HERE / "baseline_sha256.json").read_text())
    changed = [name for name, digest in baseline["source_files"].items()
               if not (ROOT / name).is_file() or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
    names = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    files = [{"path": name, "bytes": (ROOT / name).stat().st_size} for name in names if name and (ROOT / name).is_file()]
    large = [row for row in files if row["bytes"] > 10 * 1024 * 1024]
    outside = [row["path"] for row in files if not row["path"].startswith("part2_architecture_protocols/execution/")
               and row["path"] != "SecureNetworks_CaseStudy_Report.pdf"]
    private = [HERE / ".local/api/apikey.txt", HERE / ".local/ssh/lab_admin",
               HERE / ".local/media/OPNsense-25.7-dvd-amd64.iso"]
    excluded = []
    for path in private:
        result = subprocess.run(["git", "check-ignore", "--quiet", str(path)], cwd=ROOT)
        excluded.append({"path": path.relative_to(ROOT).as_posix(), "ignored": result.returncode == 0})
    # Compare actual secret values with Git-eligible content without logging them.
    secrets = [(HERE / ".local/ssh/lab_admin").read_bytes()]
    secrets += [line.split("=", 1)[1].encode() for line in (HERE / ".local/api/apikey.txt").read_text().splitlines() if "=" in line]
    leaks = []
    for row in files:
        contents = (ROOT / row["path"]).read_bytes()
        if any(secret and secret in contents for secret in secrets):
            leaks.append(row["path"])
    record = {"recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "original_source_files_checked": len(baseline["source_files"]), "original_source_files_changed": changed,
              "eligible_new_files": len(files), "eligible_new_bytes": sum(row["bytes"] for row in files),
              "largest_new_files": sorted(files, key=lambda row: row["bytes"], reverse=True)[:10],
              "files_over_10_mib": large, "files_outside_authorized_part2_scope": outside,
              "private_exclusions": excluded, "secret_values_found_in_eligible_files": leaks,
              "debug_files_moved_to_ignored_storage": moved,
              "passed": not (changed or large or outside or leaks) and all(item["ignored"] for item in excluded)}
    (HERE / "results/git_handoff.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("Original source files changed: " + str(len(changed)))
    print("Git-eligible new files: " + str(len(files)) + "; " + str(round(record["eligible_new_bytes"] / 1048576, 2)) + " MiB")
    print("Private exclusions, scope and size: " + ("PASS" if record["passed"] else "FAIL"))
    print("Debug files archived locally: " + str(len(moved)))
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
