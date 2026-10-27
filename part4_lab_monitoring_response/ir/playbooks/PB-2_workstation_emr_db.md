# PB-2 Workstation reaching for the EMR database (incident F2)

| | |
|---|---|
| **Triggers** | UC-02 (any G-03 hit), Suricata SID 9000130, IPS alerts from the source |
| **Severity** | Critical: page the on-call engineer |
| **Owner** | SOC (triage), Network (containment), IT (re-image), CISO (notification) |
| **Related rules** | G-03, R-06, C-08, H_EMR_DB |

## 1. Triage (SOC, within 10 min)
1. Confirm the source zone (`model.zone_of`) and that the destination is 192.168.10.20.
2. Identify the logged-in user from the directory (802.1X / AD logon events).
3. Check if the same host also tripped IPS rules or UC-01. A single G-03 hit with no other activity can be a mis-configured client tool; repeated hits or a 1433 sweep are treated as compromise.

## 2. Preserve
```sh
part4_lab_monitoring_response/ir/collect_evidence.sh PB2-<date>-<n> <workstation-ip>
```
Request a disk and memory image from the desktop team *before* the machine is rebooted.

## 3. Isolate and verify
* Move the port to quarantine VLAN 999 through NAC (preferred), or add a source deny with description `PB-2 <case-id>`.
* If the user is a clinician on shift, arrange a replacement workstation first.
* Verify from the same zone: `nmap -sS -Pn -p 1433 192.168.10.20` is *filtered* (verification test 3).

## 4. Rebuild
* Re-image the workstation. Rotate the user's credentials and any service account seen in the traffic.
* Review the EMR login audit for the user for the last 30 days.

## 5. Close the gap
* Find the entry point (phishing mail, USB, malicious download) and fix it.
* If personal data may have been accessed, start the DPDP breach assessment (see PB-5 step 5).

## Exit criteria
Host re-imaged, credentials rotated, entry point identified, CISO decision on notification recorded.
