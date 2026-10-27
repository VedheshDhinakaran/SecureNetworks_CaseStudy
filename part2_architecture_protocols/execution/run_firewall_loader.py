"""Part II API compatibility entry point for the unchanged Part III loader.

OPNsense 25.7 searches without an interface return floating rules only.
Query the five original interfaces so duplicate checks and setup-mode
removal operate on the actual lab rules. No repository policy is edited.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import datetime as dt
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "part3_rulebase_policy/tools"))
import opnsense_load as original
import urllib3


def interface_rules(self, contains=original.MARKER):
    found = {}
    for interface in ("lan", "opt1", "opt2", "opt3", "opt4"):
        response = self.post("firewall/filter/searchRule?interface=" + interface,
                             {"current": 1, "rowCount": -1})
        for row in response.get("rows", []):
            description = row.get("description", "")
            if description.startswith(original.MARKER + " ") and contains in description:
                found[row["uuid"]] = row
    return list(found.values())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["audit", "deduplicate", "load", "setup-on", "setup-off"])
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    original.OPNsense.our_rules = interface_rules
    key_file = HERE / ".local/api/apikey.txt"
    if args.mode in ("load", "setup-on", "setup-off"):
        argv = ["--lab-file", str(HERE / ".local/bootstrap/runtime_lab_rules.yaml"),
                "--key-file", str(key_file), "--insecure"]
        if args.apply:
            argv.append("--apply")
        if args.mode != "load":
            argv.extend(["--setup-mode", "on" if args.mode == "setup-on" else "off"])
        raise SystemExit(original.main(argv))
    credentials = dict(line.split("=", 1) for line in key_file.read_text().splitlines() if "=" in line)
    firewall = original.OPNsense("192.168.90.1", credentials["key"], credentials["secret"], False)
    rows = firewall.our_rules()
    removed = []
    if args.mode == "deduplicate":
        grouped = defaultdict(list)
        for row in rows:
            grouped[row["description"]].append(row)
        for description, group in grouped.items():
            if len(group) < 2:
                continue
            fingerprints = {json.dumps({k: v for k, v in row.items() if k != "uuid"}, sort_keys=True)
                            for row in group}
            if len(fingerprints) != 1:
                raise RuntimeError("Same description but differing rules; refusing automatic removal: " + description)
            for duplicate in group[1:]:
                print(("Removing " if args.apply else "Would remove ") + "identical duplicate: " + description)
                if args.apply:
                    firewall.del_rule(duplicate["uuid"])
                    removed.append(duplicate["uuid"])
        if removed:
            firewall.apply_with_rollback()
        rows = firewall.our_rules()
    setup = [row for row in rows if "SETUP-TEMP" in row["description"]]
    policy = [row for row in rows if "SETUP-TEMP" not in row["description"]]
    record = {"recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "original_loader_modified": False, "policy_rule_count": len(policy),
              "temporary_setup_rule_count": len(setup), "identical_duplicates_removed": removed,
              "rules": rows}
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=5, minutes=30))).strftime("%Y%m%dT%H%M%S")
    directory = HERE / "results/firewall_policy"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / (args.mode + "_" + stamp + ".json")).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("Actual lab inventory: " + str(len(policy)) + " policy rules; " + str(len(setup)) + " temporary setup rules")


if __name__ == "__main__":
    main()
