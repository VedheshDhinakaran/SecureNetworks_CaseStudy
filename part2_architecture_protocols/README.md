# Part II: Architecture, protocols and the lab build

**Owner:** Debapriya Kundu (CSE23115) · **Report:** Chapters 5, 6 and 7, and the build steps in 11.2–11.4

`network/objects.yaml` is the **single source of truth** for every zone,
VLAN, subnet, host, group and service in the project. The rule base, the
simulator, the lab loader and the log tools all read it, so an address is
changed here and nowhere else.

## Contents

| Path | What it is | Report |
|---|---|---|
| `network/objects.yaml` | Ten zones, named hosts, groups, FQDN and dynamic objects, services | Tables 5.1–5.3 |
| `tools/validate_objects.py` | Checks overlaps, gateways, host placement, duplicates and that every zone is used by a rule | 5 |
| `tools/render_docs.py` | Regenerates `docs/ip_plan.md` and `docs/architecture.dot` from the model | 5 |
| `access_layer/access_switch_hardening.ios` | 802.1X/MAB, quarantine VLAN 999, DHCP snooping, DAI, port security, PVLAN for the device VLAN. *Design reference, not tested in the lab* | 5.6, Table 5.4 |
| `access_layer/wireless_ssids.yaml` | SSID to zone mapping and security settings | 5.7 |
| `protocols/protocol_register.csv` | Secure protocol per flow, port, where it is allowed, retired protocols | Table 6.1, 6.2 |
| `lab/virtualbox/` | `create_lab.sh` / `create_lab.ps1` build the OPNsense VM (6 NICs) and four Alpine zone VMs; `snapshot_lab.sh`, `destroy_lab.sh` | 11.3, 11.4 |
| `lab/hosts/` | `setup_his.sh`, `setup_pump.sh`, `setup_rad.sh`, `setup_vendor.sh` configure each zone VM | 11.4 |
| `lab/services/` | Stand-in services: `emr_app.py` (HTTP on 443 so IPS can read it), `fake_mssql.py` (logs who reaches 1433), `mllp_server.py` / `mllp_client.py` with `hl7.py` (real MLLP framing, ORU^R01 and ACK) | 6, 11 |

## Run

```sh
cd part2_architecture_protocols/tools
python3 validate_objects.py
python3 render_docs.py && dot -Tpng ../docs/architecture.dot -o ../docs/architecture.png

# lab build (needs VirtualBox 7 and the two ISOs)
cd ../lab/virtualbox
./create_lab.sh ~/Downloads/OPNsense-25.x-dvd-amd64.iso ~/Downloads/alpine-virt-3.20.x-x86_64.iso
```

On each zone VM, after `setup-alpine`, copy this `lab/` folder to `/opt/sjv/lab`
and run the matching `hosts/setup_*.sh`. Package installation needs temporary
internet access: use `part3_rulebase_policy/tools/opnsense_load.py --setup-mode on`
and turn it **off** before any experiment.

## Limits
VirtualBox internal networks cannot emulate 802.1X, private VLANs or an HA
pair. Those are covered by the configuration reference in `access_layer/`
and by design argument in the report, not by lab evidence.
