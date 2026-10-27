"""Record the isolated firewall's non-secret rule API responses for integration checks."""
from __future__ import annotations
import json
from pathlib import Path
from seed_firewall_aliases import HERE, OPNsense
import urllib3


def main() -> None:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    credentials = dict(line.split("=", 1) for line in
                       (HERE / ".local/api/apikey.txt").read_text().splitlines() if "=" in line)
    firewall = OPNsense("192.168.90.1", credentials["key"], credentials["secret"], False)
    record = {}
    for name, body in [("all", {"current": 1, "rowCount": -1}),
                       ("tagged_search", {"current": 1, "rowCount": -1, "searchPhrase": "[cs07]"})]:
        response = firewall.post("firewall/filter/searchRule", body)
        record[name] = response
        print(name + ": " + str(len(response.get("rows", []))) + " rows")
        for row in response.get("rows", [])[:3]:
            print(json.dumps(row, ensure_ascii=True))
    for interface in ["lan", "opt1", "opt2", "opt3", "opt4"]:
        response = firewall.post("firewall/filter/searchRule?interface=" + interface,
                                 {"current": 1, "rowCount": -1})
        record[interface] = response
        print(interface + ": " + str(len(response.get("rows", []))) + " rows")
        for row in response.get("rows", [])[:1]:
            print(json.dumps(row, ensure_ascii=True))
    (HERE / "results/firewall_api_audit.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
