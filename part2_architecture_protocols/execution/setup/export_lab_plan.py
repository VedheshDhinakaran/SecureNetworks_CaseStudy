"""Export the existing Part II objects and Part III lab mapping for setup."""
import json
import re
import shlex
from pathlib import Path

import yaml

PART2 = Path(__file__).resolve().parents[2]
EXECUTION = PART2 / "execution"
objects = yaml.safe_load((PART2 / "network/objects.yaml").read_text(encoding="utf-8"))
lab = yaml.safe_load((PART2.parent / "part3_rulebase_policy/opnsense/lab_rules.yaml").read_text(encoding="utf-8"))
zones = {"MGMT": "Z_MGMT", "HIS": "Z_HIS", "DEVICES": "Z_DEVICES",
         "RADIOLOGY": "Z_RADIOLOGY", "VENDOR": "Z_VENDOR_WIFI"}
interfaces = {}
for name, zone in zones.items():
    z = objects["zones"][zone]
    definition = lab["interfaces"][name]
    if z["subnet"] != definition["subnet"]:
        raise SystemExit("Lab and production subnet disagree: " + name)
    interfaces[definition["opnsense_id"]] = {
        "device": definition["device"], "description": name,
        "address": z["gateway"], "prefix": int(z["subnet"].split("/")[1]),
    }
plan = {"interfaces": interfaces, "vendor_dhcp": lab["interfaces"]["VENDOR"]["dhcp"],
        "source": ["part2_architecture_protocols/network/objects.yaml",
                   "part3_rulebase_policy/opnsense/lab_rules.yaml"]}
plan["hosts"] = {name: value["ip"] for name, value in objects["hosts"].items()}
plan["lab_hosts"] = {}
for role, script, interface in [("his-vm", "his", "opt1"), ("pump-vm", "pump", "opt2"),
                                ("rad-vm", "rad", "opt3")]:
    text = (PART2 / ("lab/hosts/setup_" + script + ".sh")).read_text()
    arguments = shlex.split(re.search(r"^write_static (.+)$", text, re.MULTILINE).group(1))
    if arguments[1] != interfaces[interface]["address"]:
        raise ValueError("Host setup gateway differs from the existing lab plan")
    plan["lab_hosts"][role] = {"addresses": [value.split("/")[0] for value in [arguments[0], *arguments[2:]]],
                                "gateway": arguments[1]}
plan["lab_hosts"]["vendor-vm"] = {"gateway": interfaces["opt4"]["address"], "dhcp": plan["vendor_dhcp"]}
out = EXECUTION / ".local/bootstrap"
out.mkdir(parents=True, exist_ok=True)
(out / "firewall_plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
(EXECUTION / "results/lab_network_plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
print("Exported the existing interface addresses and DHCP range; source files unchanged")
