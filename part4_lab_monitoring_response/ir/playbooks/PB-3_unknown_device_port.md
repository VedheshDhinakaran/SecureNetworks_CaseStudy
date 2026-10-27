# PB-3 Unknown device on a medical-device port (incident F1)

| | |
|---|---|
| **Triggers** | NAC new-MAC alert, MAB failure, port-security violation |
| **Severity** | Medium (High if the device obtained a VLAN 30 address) |
| **Owner** | Network, Biomed |
| **Related controls** | 802.1X/MAB, quarantine VLAN 999, DHCP snooping, DV-04 |

## 1. Triage
1. Read the switch, port and MAC from the NAC alert. Look up the MAC vendor (OUI).
2. Confirm the port is in VLAN 999 (`show authentication sessions interface <port>`).
3. Check that the MAC has **no** DHCP lease in VLAN 30 and **no** flows through the firewall from 192.168.30.0/24 with that MAC.

## 2. Preserve
Export switch logs, the NAC session record and the DHCP snooping binding table. Ask facilities for CCTV covering the location for the time window.

## 3. Isolate and verify
The port is already isolated by design (VLAN 999 has no gateway). Shut the port administratively if the device keeps retrying. Verify nothing from that MAC appears in the firewall logs.

## 4. Rebuild
Biomed physically inspects the location. If the device is a legitimate new medical device, it is registered (MAB entry, MDS2 form, flows reviewed) through the normal change path, never by unblocking the port ad hoc.

## 5. Close the gap
Lock or relocate exposed ports in public areas. Brief engineers and contractors on the device onboarding process.

## Exit criteria
Device identified and removed or registered, port state reviewed, incident logged.
