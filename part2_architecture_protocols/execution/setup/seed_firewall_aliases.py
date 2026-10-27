"""Create the original lab aliases before running the unchanged Part III loader.

OPNsense 25.7 returns [] for a missing alias UUID. The existing loader calls
.get() on that response. Seeding the same aliases first avoids editing it.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import urllib3

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "part3_rulebase_policy" / "tools"))
from opnsense_load import OPNsense, ObjectModel, LAB_FILE, alias_payloads, yaml


def main() -> None:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    credentials = dict(line.split("=", 1) for line in
                       (HERE / ".local/api/apikey.txt").read_text().splitlines() if "=" in line)
    firewall = OPNsense("192.168.90.1", credentials["key"], credentials["secret"], False)
    lab = yaml.safe_load(LAB_FILE.read_text(encoding="utf-8"))
    records = []
    for alias in alias_payloads(lab, ObjectModel.load()):
        found = firewall.get("firewall/alias/getAliasUUID/" + alias["name"])
        if found == [] or found == {} or (isinstance(found, dict) and not found.get("uuid")):
            response = firewall.post("firewall/alias/addItem", {"alias": alias})
            if response.get("result") != "saved":
                raise RuntimeError("Alias was not saved: " + alias["name"] + " " + str(response))
            status = "created from original loader payload"
        elif isinstance(found, dict) and found.get("uuid"):
            status = "already exists"
        else:
            raise RuntimeError("Unexpected alias lookup response: " + str(found))
        records.append({"name": alias["name"], "status": status})
        print(alias["name"] + ": " + status)
    # The API accepts one port or a named alias, whereas the source policy
    # expresses the vendor web rule as "80,443". Preserve those exact ports
    # in an appliance alias and generate a local loader input copy.
    conversions = []
    for rule in lab["rules"]:
        value = str(rule.get("port", ""))
        if "," not in value:
            continue
        ports = value.split(",")
        if not all(port.isdigit() and 1 <= int(port) <= 65535 for port in ports):
            raise ValueError("Unsupported comma-separated port expression")
        name = "CS07_PORTS_" + "_".join(ports)
        payload = {"name": name, "type": "port", "content": "\n".join(ports),
                   "enabled": "1", "description": "[cs07] API representation of " + value}
        existing = firewall.get("firewall/alias/getAliasUUID/" + name)
        if isinstance(existing, dict) and existing.get("uuid"):
            firewall.post("firewall/alias/setItem/" + existing["uuid"], {"alias": payload})
        elif existing in ([], {}):
            firewall.post("firewall/alias/addItem", {"alias": payload})
        else:
            raise RuntimeError("Unexpected port alias lookup response")
        rule["port"] = name
        conversions.append({"rule": rule["descr"], "original_ports": value, "equivalent_alias": name})
        print("Equivalent API port alias: " + value + " -> " + name)
    runtime = HERE / ".local/bootstrap/runtime_lab_rules.yaml"
    runtime.parent.mkdir(parents=True, exist_ok=True)
    runtime.write_text(yaml.safe_dump(lab, sort_keys=False), encoding="utf-8")
    firewall.post("firewall/alias/reconfigure")
    (HERE / "results" / "alias_bootstrap.json").write_text(json.dumps({
        "reason": "Missing alias UUID is [] on OPNsense 25.7; original loader expects a mapping",
        "original_loader_modified": False, "original_policy_modified": False,
        "aliases": records, "equivalent_port_representations": conversions,
        "generated_loader_input": ".local/bootstrap/runtime_lab_rules.yaml"}, indent=2) + "\n", encoding="utf-8")
    print("Use the unchanged loader with --lab-file " + str(runtime))


if __name__ == "__main__":
    main()
