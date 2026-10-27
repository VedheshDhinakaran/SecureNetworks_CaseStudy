# PB-4 Compromised medical device

| | |
|---|---|
| **Triggers** | UC-03 (DV-05 internet egress), IPS alerts on DV-03 (SIDs 9000120-9000122), long DNS queries (SID 9000140) |
| **Severity** | High. Patient safety takes priority over containment speed |
| **Owner** | Biomed (device), Network (isolation), Clinical lead (bedside replacement) |
| **Related rules** | DV-01..DV-05 |

> **Never shut down the whole device VLAN.** That is itself a patient-safety incident. Isolate one device at a time.

## 1. Triage
1. Identify the device from its IP (asset register: `part1_foundations_threats_risk/risk/assets.csv`), its ward and whether it is in use on a patient.
2. Check the device's recent DV-01..DV-03 flows for changes in volume or destination.

## 2. Preserve
```sh
part4_lab_monitoring_response/ir/collect_evidence.sh PB4-<date>-<n> <device-ip>
```
Start a port capture on the access switch (SPAN) for 15 minutes. Biomed exports the device's own log buffer.

## 3. Isolate (only after a replacement is at the bedside)
1. Clinical lead confirms a replacement device is in place.
2. Network moves that single port to VLAN 999, or adds a host deny above DV-01 with description `PB-4 <case-id>`.
3. Verify the device no longer appears in DV-01..DV-03 counters (`hit_counter_review.py --only DV-0`).

## 4. Rebuild
Vendor re-flashes the device through the VENDOR-MAINT process (ticket, IPsec, jump host, VM-02 per-ticket rule). The device returns to service only after biomed signs off.

## 5. Close the gap
Review the device's MDS2 form. Tighten its flows if it needed fewer than DV-01..DV-03 allow. Report to the manufacturer if a vulnerability is suspected (IEC 80001-1).

## Exit criteria
Device re-flashed and verified, flows reviewed, manufacturer informed where relevant.
