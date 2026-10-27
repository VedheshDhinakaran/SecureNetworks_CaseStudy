# Part II - Implementation and Validation Record

## Scope and evidence status

Prepared for Part II by Debapriya Kundu (CSE23115), 2026-10-27T23:15:57+05:30. This implementation record supplements Chapters 5, 6 and 7 and the lab foundation in Sections 11.2-11.4. It distinguishes proposed production controls, executed offline checks, local service checks and actual firewall-lab evidence. The report's expected-result cells are not observations. Joint experiments E1-E8 remain pending unless their real captures are explicitly cited. No hospital production network or patient data was used.

## Original source preservation

| Item | Recorded status |
|---|---|
| Existing tracked source files changed by this work | 0 |
| Offline evidence | execution/results/offline_20261027T175111 |
| Local service evidence | execution/results/local_services_20261027T175339 |
| Firewall lab evidence verified | True |
| Current lab stage | Part II lab ready: five disk-booted VMs; original zone scripts completed; 18 policy rules; zero temporary setup rules; 35 readiness checks and seven PF-log block correlations passed after reboot |

## Offline validation actually executed

| Existing check | Observed result |
|---|---|
| part2 unit tests | PASS (exit 0) |
| object validation | PASS (exit 0) |
| policy lint | PASS (exit 0) |
| policy probes | PASS (exit 0) |
| lab subset | PASS (exit 0) |
| all existing tests | PASS (exit 0) |

## Meaning of the offline results

The existing Part II unit suite covers 9 tests; the full existing suite contains 42 tests. The policy verification command exercises 30 simulator probes, and the subset checker examines 18 lab rules including documented broader and lab-only cases. A passing result establishes behaviour of the written model and tools; it does not establish that a deployed firewall enforces the policy. Full command lines, stdout, stderr, exit codes and SHA256 manifests are retained in the cited results directory.

## Original stand-in services exercised over sockets

| Local integration check | Observed result |
|---|---|
| emr http health | PASS |
| emr http portal test | PASS |
| mssql tcp listener | PASS |
| hl7 valid observation ack | PASS |
| hl7 malformed message rejected | PASS |
| original mllp client | PASS |

## Service-test boundaries

The original Python programs were started as separate processes on 127.0.0.1 with temporary ports. Checks exercised HTTP health and portal responses, TCP listener reachability, a valid HL7 observation and matching ACK, rejection of a malformed message, and the original MLLP client. These connections did not cross OPNsense. The EMR uses clear-text HTTP on port 443 in the lab so IPS can read it; it is not evidence of production HTTPS. The MSSQL stand-in accepts TCP connections and does not implement SQL or TDS. The HL7 service is a minimal demonstrator.

## Real firewall-lab readiness observations

| Actual VM readiness check group | Observed result |
|---|---|
| bastion | 6 checks; PASS |
| his-vm | 7 checks; PASS |
| pump-vm | 8 checks; PASS |
| rad-vm | 8 checks; PASS |
| vendor-vm | 6 checks; PASS |
| Loaded policy / temporary setup rules | 18 / 0 |
| Blocked connections corroborated in PF packet log | 7 of 7 |

## Evidence and installed environment

The lab was built with VirtualBox 7.2.22, OPNsense 25.7 (FreeBSD 14.3-RELEASE-p1), and four Alpine 3.20.10 guests running kernel 6.6.142-0-virt. Windows is the MGMT bastion, not a sixth VM. All five VMs were restarted after configuration; the guests then booted from their disks with their planned addresses. The test run is retained in execution/results/readiness_20261027T222816. Per-host JSON and transcripts, the active 18-rule API inventory, decoded PF log and a 22.0 KiB packet capture record the observations. All 35 readiness checks passed. The temporary package server was stopped, setup rules removed and stale zone states cleared before these checks.

## What the real checks establish

The MGMT host reached all four SSH services and the live database listener. The pump used internal UDP/TCP DNS, NTP and HL7 with an AA acknowledgement, while EMR, database and public web access were blocked. Radiology reached the EMR; its broker alias sent HL7, while the reading workstation's HL7 and database connections were blocked. Vendor DHCP assigned 10.61.0.50, firewall DNS and public HTTP/HTTPS worked, and internal EMR/DB access was blocked. All seven denied connections matched actual block entries in the PF packet log. DNS recursion used source 192.168.10.53, and upstream NTP used .57, as shown by pass entries. The measured internal NTP response was stratum 3 with leap status 0; this is not proof of the production stratum-2 or NTS design.

## Lab foundation: fixed interface and address mapping

| VM / interface | Network and role |
|---|---|
| opnsense em0 / WAN | VirtualBox NAT for upstream access |
| opnsense em1 / LAN | MGMT host-only; firewall 192.168.90.1, bastion 192.168.90.5 |
| his-vm / em2 OPT1 | 192.168.10.0/24; DB .20, EMR .21, interface engine .40, DNS .53, NTP .57 |
| pump-vm / em3 OPT2 | 192.168.30.10/24; gateway 192.168.30.1 |
| rad-vm / em4 OPT3 | 192.168.40.100/24 and broker alias .12; gateway .1 |
| vendor-vm / em5 OPT4 | 10.61.0.0/24; DHCP .50-.99; gateway 10.61.0.1 |

## Architecture and protocol consistency

The original objects.yaml and production addresses are preserved. The production design contains ten zones; the lab represents HIS, DEVICES, RADIOLOGY, VENDOR-WIFI and MGMT. Internal clinical/device/research DNS flows use H_DNS; guest/vendor production policy permits public DNS, and this lab uses the firewall resolver for vendor clients. Therefore the protocol register's phrase 'all zones to H_DNS only' needs this explicit exception when interpreting Chapter 6. DNSSEC, authenticated NTP/NTS, TLS logging and TLS interception are proposed production controls, not demonstrated by the local service tests.

## CIA argument and controls outside the lab

Confidentiality depends on scoped access and appropriate encryption; a permitted port alone does not supply encryption. Integrity depends on narrow permissions, protocol validation and the inspection engines actually enabled. Availability depends on correctly working DNS, time, state tracking and operational change control. HA, NAC/802.1X and private VLAN enforcement remain design/configuration references; this five-VM lab cannot demonstrate physical-switch peer isolation or HA failover. No claim of measured production performance is made.

## Design assumptions requiring team review

The report describes over 1,000 clinical PCs while Z_CLINICAL is a /23 with 510 usable addresses, including its gateway. The original brief does not supply that endpoint count. The capacity assumption must be clarified before a production rollout; this work does not change addressing behind Part III's rules. The brief's illustrative radiology-to-SQL permit is intentionally replaced by denial plus broker HL7 in the team design. Retain the Chapter 9 justification and validate the legitimate business-flow requirement with the policy owner.

## Integration adaptations with original source preserved

OPNsense 25.7 returns an empty list for missing alias UUIDs, rejects a comma-separated destination-port expression, and searches floating rules when no interface is supplied. Part II helpers pre-create the original aliases, represent exactly ports 80 and 443 with a port alias, and search the five original interfaces. Failed-load duplicates were removed; the final inventory contains exactly 18 intended rules. Windows CRLF was normalized only in deployed shell-script copies. Stopping DNS/NTP before initial configuration avoided an observed OpenRC restart race. Guest configuration binds outbound DNS/NTP to .53/.57. Interrupted package downloads were recovered using the same official signed APKs cached through Windows; Alpine signature verification remained enabled, repositories were restored and the temporary server stopped. Four temporary Windows routes send only lab-subnet traffic through 192.168.90.1; they do not replace the laptop's default route and must be re-created after a Windows reboot. All original tracked project files remain unchanged.

## Sharing and reproduction

All new project artefacts are under part2_architecture_protocols/execution. Downloaded media, temporary files and the unmodified input report backup are under ignored .local. Run run_offline_checks.py, fetch_lab_media.py and verify_local_services.py from this directory using Python, or follow execution/README.md from the repository root. Review the default dry run of create_lab_windows.ps1, then use -Create with an optional -VmDirectory. VM disks are local working data on a drive with enough space; their location is configurable and does not affect the addresses shared by the team.

## Handoff and completion gate

Part II hands over installed zone hosts and services, stable addressing, interface mapping, actual environment versions and evidence of readiness. Part III owns the firewall rule base. Part IV leads E1-E8 and the Observed cells in Table 11.2. A complete Part II VM handoff requires installed operating systems, working DNS/NTP/HTTP/MLLP, rules loaded and setup access removed, plus real permitted/blocked flow checks with firewall logs. Part II readiness has been demonstrated by the cited run. Shared E1-E8, their full captures, Part IV collector integration and the Observed cells remain the team's next work. App-ID, Suricata IPS, physical NAC/PVLAN and HA are not established by these readiness checks.
