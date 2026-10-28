# Import and run the CS07 hospital lab on another computer

This is the Part II handoff to the teammate running Part IV. It transfers the
existing five installed VMs; do not run the blank-VM builder or reinstall Alpine
or OPNsense after importing. Chapters 5-7 describe the design, Sections 11.2-11.4
describe its implementation, and Part IV runs E1-E8 on this foundation.

## 1. Files to receive

Get the latest project repository, including this guide, and receive these
three files privately from Debapriya:

| File | Purpose |
|---|---|
| `CS07_Hospital_Lab.ova` | OPNsense and all four installed Alpine guests |
| `CS07_Hospital_Lab.ova.sha256` | Checksum for the appliance |
| `CS07_Lab_Access_PRIVATE.zip` | Dedicated team SSH key, lab API access, console-login details and runtime policy copy |

On the source computer they are under
`part2_architecture_protocols/execution/.local/appliance/`. Share them using
private shared storage or USB. The OVA contains lab credentials too. These
files stay out of Git; the guide, helpers and the non-secret export manifest
`../results/appliance_export.json` belong in Git. The appliance's actual size
and SHA256 are in that manifest.

## 2. Install the host tools

The detailed commands below target a Windows Intel/AMD x86-64 laptop, matching
the source machine. Use a drive with about **40 GB free** for the imported
disks, transfer files and optional WSL installation. The five guests allocate
**6 GiB RAM** in total and have **28 GiB combined virtual disk capacity**;
the source laptop had 16 GB RAM. Enable CPU virtualisation in firmware if
VirtualBox reports that it is unavailable.

Install:

1. **VirtualBox 7.2.22 base package**, matching the export version. The Extension
   Pack and guest installer ISOs are not needed. Use the official
   [VirtualBox downloads](https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html).
2. **Python 3.10 or newer**, with `python` usable in PowerShell.
3. **Windows OpenSSH Client** (Windows Settings > Optional features) if `ssh`
   is not installed. Git is useful for cloning the repository; downloading the
   repository ZIP also works for the import/run steps.
4. **WSL Ubuntu** for the original Part IV bastion `.sh` scripts, if you do not
   already have a Linux shell. From Administrator PowerShell:

   ```powershell
   wsl --install -d Ubuntu
   ```

   Restart if requested and complete Ubuntu's first-run username/password
   setup. WSL is the host's command shell here, not an additional lab zone.
   [Microsoft installation instructions](https://learn.microsoft.com/en-us/windows/wsl/install).

Open PowerShell in the repository root and install the two Python packages
needed by the existing firewall/readiness helpers:

```powershell
python -m pip install requests pyyaml
```

These are archived guest releases pinned for the team's case-study lab:
OPNsense 25.7 and Alpine 3.20.10. Keep this as an isolated teaching lab.

## 3. Verify the transfer and import all five VMs

Keep the downloaded appliance outside Git. In repository-root PowerShell,
replace the first path with your actual download location:

```powershell
$Ova = 'C:\CS07_Transfer\CS07_Hospital_Lab.ova'
$manifest = Get-Content .\part2_architecture_protocols\execution\results\appliance_export.json -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $Ova -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.appliance_sha256) {
    throw 'Appliance checksum mismatch; transfer it again before importing.'
}
```

In VirtualBox choose **Home > Import** (or **File > Import Appliance**, depending
on the interface), select the OVA, and review the five machines:

| VM name, keep exactly | RAM | CPU | Role |
|---|---:|---:|---|
| `opnsense` | 4096 MB | 2 | Firewall/router |
| `his-vm` | 512 MB | 1 | HIS service stand-ins, DNS and NTP |
| `pump-vm` | 512 MB | 1 | Medical-device client |
| `rad-vm` | 512 MB | 1 | Radiology workstation and broker alias |
| `vendor-vm` | 512 MB | 1 | Vendor client |

Set **Base Folder** to `<your user profile>\VirtualBox VMs\CS07`, or another
location with enough room. Select **Keep all network adapter MAC addresses**
so the vendor's saved DHCP lease stays consistent. You may select **Import
Hard Drives as VDI**. Import all five machines and leave them **powered off**.
If these names already exist, use a separate clean VirtualBox environment;
do not overwrite another lab. The following helper requires the exact names.

For a command-line preview only:

```powershell
$VBox = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
& $VBox import $Ova --dry-run
```

[Oracle appliance import/export instructions](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/working-with-vms.html).

## 4. Reconnect the imported networks on your computer

Importing does not create this PC's management interface or Windows routes.
The source host-only adapter's name will usually differ from yours.

From the repository root, first review the dry run:

```powershell
.\part2_architecture_protocols\execution\appliance\configure_imported_lab_windows.ps1
```

Then run the same command **in Administrator PowerShell**, with `-Apply`:

```powershell
.\part2_architecture_protocols\execution\appliance\configure_imported_lab_windows.ps1 -Apply
```

If you chose another Base Folder, pass the same `-VmDirectory 'E:\MyLab\CS07'`
to both commands. If execution policy blocks the helper, use
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script path> -Apply`
for this invocation; no permanent execution-policy change is needed.

The helper verifies all five registered paths and that every guest is off.
It creates/reuses only the lab's host-only interface, reconnects the original
internal networks, and adds four temporary lab routes. It does not replace
your normal default/internet route or change firewall policy.

| Firewall adapter / guest interface | Attachment | Address |
|---|---|---|
| 1 / `em0` WAN | NAT | DHCP from VirtualBox |
| 2 / `em1` MGMT | Your host-only adapter | Firewall `192.168.90.1/24`; Windows host `192.168.90.5/24` |
| 3 / `em2` HIS | Internal `sjv-his` | Gateway `192.168.10.1/24` |
| 4 / `em3` DEVICES | Internal `sjv-devices` | Gateway `192.168.30.1/24` |
| 5 / `em4` RADIOLOGY | Internal `sjv-radiology` | Gateway `192.168.40.1/24` |
| 6 / `em5` VENDOR | Internal `sjv-vendor` | Gateway `10.61.0.1/24` |

Each Alpine VM has one internal NIC on its corresponding network. Do not
switch the zone VMs to NAT or bridged mode: that bypasses the intended path.

## 5. Install the private lab access files

From repository-root PowerShell, verify the access ZIP and extract it into
the execution folder:

```powershell
$AccessZip = 'C:\CS07_Transfer\CS07_Lab_Access_PRIVATE.zip'
if ((Get-FileHash -LiteralPath $AccessZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.access_bundle_sha256) {
    throw 'Access ZIP checksum mismatch.'
}
Expand-Archive -LiteralPath $AccessZip -DestinationPath .\part2_architecture_protocols\execution
$Key = (Resolve-Path .\part2_architecture_protocols\execution\.local\ssh\lab_admin).Path
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls.exe $Key /inheritance:r /grant:r ('{0}:(R)' -f $Identity)
```

All ZIP members extract under ignored `.local/`. Read
`execution/.local/appliance/ACCESS_README_PRIVATE.txt` for GUI and console
logins. The bundle uses a **dedicated team key**, not Debapriya's original
administration key. The API credentials are for this lab firewall only.
Do not copy these private contents into the report or public evidence.

## 6. Boot and verify your imported lab

Start `opnsense` in VirtualBox first. Wait for its console menu and web GUI;
on a Windows Hyper-V backend boot can take several minutes. Then start the
four Alpine machines. Every VM already boots from its installed disk.

Open `https://192.168.90.1` and use the private access notes. The certificate
is self-signed for this isolated firewall. Guest addresses are:

| Guest | Addresses |
|---|---|
| HIS | `192.168.10.20` DB TCP listener; `.21` EMR HTTP on 443; `.40` HL7/MLLP; `.53` DNS; `.57` NTP |
| Device | `192.168.30.10` |
| Radiology | `192.168.40.100`; broker alias `192.168.40.12` |
| Vendor | DHCP, normally `10.61.0.50` with the preserved MAC |

From repository-root PowerShell:

```powershell
python -B part2_architecture_protocols/execution/lab_ssh.py his-vm --command "ip -4 addr show; ip route"
python -B part2_architecture_protocols/execution/run_firewall_loader.py audit
python -B part2_architecture_protocols/execution/run_lab_readiness.py --run
```

Expect **18 policy rules**, **zero setup rules**, **35 passing checks**, and
**seven blocked-flow log confirmations**. The seven are included within the
35. These are your imported machine's readiness results, not E1-E8 results.
If the firewall is still booting, wait for its GUI before retrying.

The vendor's DHCP address must be checked in its console with `ip -4 addr`.
The helpers use `.50`; if it changed, restore the intended lease/reservation
to `.50` in the firewall and renew the lease before using these fixed helpers.

After a Windows restart, rerun only this command as Administrator to restore
the temporary routes; do not recreate or reimport the VMs:

```powershell
.\part2_architecture_protocols\execution\configure_host_routes.ps1 -Apply
```

## 7. Prepare the host shell and remote log collection

The zone scripts are already at
`/opt/sjv/part4_lab_monitoring_response/experiments` in every Alpine guest.
The original source is preserved; deployed `.sh` copies use Unix LF endings.
For bastion steps, use WSL Ubuntu on the Windows host. It does not need
mirrored networking or an additional VirtualBox VM for this procedure.

In Ubuntu, install the host-side shell/Python tools:

```sh
sudo apt-get update
sudo apt-get install -y openssh-client python3 python3-yaml
# Change this example to your actual Windows repository path:
cd /mnt/d/SecureNetworks_CaseStudy
python3 part2_architecture_protocols/execution/appliance/prepare_bastion_runtime.py
export CS07_RUNTIME="$(pwd)/part2_architecture_protocols/execution/.local/part4_runtime"
mkdir -p ~/.ssh
cp part2_architecture_protocols/execution/.local/ssh/lab_admin ~/.ssh/cs07_lab_admin
chmod 700 ~/.ssh
chmod 600 ~/.ssh/cs07_lab_admin
cat >> ~/.ssh/config <<'EOF'

Host 192.168.90.1 192.168.10.20 192.168.30.10 192.168.40.100 10.61.0.50
    User root
    IdentityFile ~/.ssh/cs07_lab_admin
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
EOF
chmod 600 ~/.ssh/config
ssh root@192.168.90.1 'hostname'
ssh root@192.168.10.20 'hostname'
sudo mkdir -p /opt/sjv/results
sudo chown "$(id -u):$(id -g)" /opt/sjv/results
```

The runtime preparation copies the original public scripts/tools and converts
CRLF to LF only in copied shell files. Run host-side scripts from this runtime
so a Windows Git checkout cannot break shell parsing. It leaves original source
and collected evidence intact. Set `CS07_RUNTIME` again in each new WSL terminal.

Use `ROLE=bastion` when running original bastion scripts in WSL: its virtual
interface does not advertise Windows' `192.168.90.5`, so auto-detection alone
would not recognise it. Windows' lab routes must already exist. If WSL SSH
cannot reach the firewall, check Windows SSH first, restart WSL after setting
the routes, and verify its outbound access before running experiments.

For logs, run the supplied Windows-host receiver in a **separate PowerShell
window**, from the repository root, and leave it running:

```powershell
python -B part2_architecture_protocols/execution/appliance/collect_syslog_windows.py
```

It listens only on `192.168.90.5:514/UDP`, accepts only the firewall's
`192.168.90.1`, and saves raw datagrams under `execution/.local/collector/`.
It keeps at most two 16 MiB files; preserve each experiment's evidence before
logs rotate. This small lab receiver substitutes for the original Linux
rsyslog process, and does not implement production TLS/180-day retention.

Allow that one inbound flow in **Administrator PowerShell**:

```powershell
if (-not (Get-NetFirewallRule -Name CS07LabSyslog -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name CS07LabSyslog -DisplayName 'CS07 lab syslog' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 514 -LocalAddress 192.168.90.5 -RemoteAddress 192.168.90.1 -Profile Any
}
```

In OPNsense, **System > Settings > Logging > Remote**, add an enabled target:
UDP IPv4, host `192.168.90.5`, port `514`, application `filterlog` (and
Suricata when available). Apply. Generate one blocked lab connection and
confirm that the receiver saves a real `filterlog` line. Do this before E8.
[OPNsense remote logging settings](https://docs.opnsense.org/manual/settingsmenu.html).

The existing E2/E8 bastion scripts read `/var/log/opnsense.log`. In WSL, link
that filename to the Windows receiver's file after it has started:

```sh
cd /mnt/d/SecureNetworks_CaseStudy  # replace with your actual repo path
LOG_FILE="$(pwd)/part2_architecture_protocols/execution/.local/collector/opnsense.log"
# Run only if /var/log/opnsense.log does not already exist:
sudo ln -s "$LOG_FILE" /var/log/opnsense.log
tail -5 /var/log/opnsense.log
```

If using a native Linux host instead, configure its MGMT interface/routes
with the same addresses and use the existing
`part4_lab_monitoring_response/monitoring/rsyslog-opnsense.conf` as documented
there. The Windows `.ps1`/native-SSH readiness helpers are Windows-specific.

## 8. Run Part IV's experiments

Use `part4_lab_monitoring_response/README.md` and each script's phase prompts.
Open the required guest terminals and the firewall GUI together. For example,
open an interactive SSH session from PowerShell (not the non-interactive
`lab_ssh.py --command` wrapper):

```powershell
$Key = (Resolve-Path .\part2_architecture_protocols\execution\.local\ssh\lab_admin).Path
ssh -i $Key root@192.168.40.100
```

Inside radiology, after setting the requested E2 GUI state:

```sh
cd /opt/sjv/part4_lab_monitoring_response/experiments
sh e2_segmentation.sh
```

For E2's bastion step, in WSL at your repository root:

```sh
ROLE=bastion sh "$CS07_RUNTIME/part4_lab_monitoring_response/experiments/e2_segmentation.sh"
```

Do not run all scripts unattended. Some pause for GUI changes, and E4 requires
coordination between terminals. Remove temporary experimental allow-all,
reverse and floating rules after their experiment, and clear affected states
when comparing rule order or filtering behaviour. Retain before/after evidence.

| Experiment | Run on | Additional preparation |
|---|---|---|
| E1 baseline | Radiology, vendor | Temporary allow-all rules; remove afterwards |
| E2 segmentation | Radiology, vendor, bastion | Original 18-rule policy; remote log collector for bastion extract |
| E3 device restrictions | Device, bastion | Original policy; collect firewall counters |
| E4 stateless/stateful | Radiology, HIS, bastion | Coordinate the four GUI/terminal phases; restore stateful policy |
| E5 rule order | Vendor, bastion | Compare broad-pass ordering; remove the test rule afterwards |
| E6 IPS | Radiology, vendor | Configure Suricata IPS and the required rules, then compare off/on |
| E7 App-ID | HIS, radiology | Install/configure Zenarmor; compare off/on; restore the EMR service |
| E8 timeline | Radiology, vendor, bastion | Working remote logs, synchronised clocks and attempt-time files |

The baseline policy was installed through OPNsense's firewall automation API.
In 25.7 inspect the **Firewall > Automation** filter rules (newer releases may
call this **Rules [new]**). Make ordering comparisons in the same rule system;
do not assume a rule added in a separate legacy tab sits above the API rules.
Apply changes and verify the actual PF rules/counters before taking evidence.
[OPNsense rule ordering](https://docs.opnsense.org/manual/firewall.html).

### E6 and E7 require additional engine configuration

The OVA provides the verified Part II foundation. It does not claim that IPS,
App-ID, HA or physical-switch NAC/PVLAN were demonstrated.

For E6, follow Part IV's README and `ids/suricata/` files: disable hardware
checksum/TSO/LRO offloading under Interfaces > Settings, select the appropriate
zone interfaces, enable IPS, download the required ET Open sets, load the
original local rules and apply the intended drop policy. Capture the enabled
configuration and actual alerts/drops. Take a baseline snapshot before changes.
[OPNsense IPS instructions](https://docs.opnsense.org/manual/ips.html).

The original `sjv-custom.xml` header supplies the local-rules download method.
From repository-root PowerShell, copy the metadata with the team key:

```powershell
scp -i $Key part4_lab_monitoring_response/ids/suricata/sjv-custom.xml root@192.168.90.1:/usr/local/opnsense/scripts/suricata/metadata/rules/
python -m http.server 8000 --bind 192.168.90.5 --directory part4_lab_monitoring_response/ids/suricata
```

Leave the server running in that separate window while downloading the local
rules, and allow TCP 8000 only from `192.168.90.1` to local `192.168.90.5` in
Windows Firewall if needed. In Services > Intrusion Detection > Download,
enable `sjv/sjv-custom` and download/update. Check that the local signatures
actually appear before testing; the supplied metadata explicitly asks you to
verify its format/path against the installed OPNsense version. Stop this
temporary server after the download. Do not claim E6's IPS-on phase until
the engine and required signatures are active.

For E7, follow the original script and install/configure the available
Zenarmor edition through OPNsense's supported plugin workflow. Record the
version, interfaces and exact features the edition exposes. If classification
or blocking is unavailable, report that limitation rather than assuming the
expected result. Coordinate IPS/App-ID interface use with their documentation.
The HIS EMR normally starts at boot; after E7 stop the temporary SSH-on-443
listener and restore only the EMR process, or reboot HIS to its baseline and
verify its service listeners before another test.

For E4, OPNsense/FreeBSD command names can differ from Linux (`timeout`, for
example). Check the recorded exit codes; if a bundled script's command is
unavailable, record that error and capture the equivalent operation manually.
The original Part IV scripts are preserved as supplied, not certified by this
appliance export. GUI engine/edition differences are findings to document.

## 9. Collect real results and complete the report

Guest transcripts are under `/opt/sjv/results/E<n>/`. After running the
required guest and bastion steps, collect them in WSL from the repository:

```sh
cd /mnt/d/SecureNetworks_CaseStudy  # replace with your actual repo path
export CS07_RUNTIME="$(pwd)/part2_architecture_protocols/execution/.local/part4_runtime"
VENDOR_IP=10.61.0.50 sh "$CS07_RUNTIME/part4_lab_monitoring_response/experiments/collect_results.sh"
# Copy the collected output from the runtime into Part IV's evidence folder:
cp -r "$CS07_RUNTIME/part4_lab_monitoring_response/evidence/raw" part4_lab_monitoring_response/evidence/
```

This collects into the runtime first, then copies Part IV's `evidence/raw/`
and `SHA256SUMS` into the repository. Check that
each required VM was reached; a script that reports a copy failure has not
collected that VM's evidence. The collector keeps raw transcripts, and it
does not invent Observed results. Preserve the receiver's real log alongside
each relevant experiment. For E8 combine the real radiology/vendor attempt-time
records, then use the printed `timeline.py` command against the saved log and
`rules_debug.txt`.

Fill `part4_lab_monitoring_response/evidence/E1/README.md` through E8, the actual
environment versions, and the configuration-export checklist. Transfer only
observed results to report Table 11.2 and the verification matrix's
`observed_in_lab` column. Your imported environment details and new experiment
captures belong to your run; the source machine's 35 readiness checks are
handoff evidence and are not replacements for E1-E8.

The lab EMR is intentionally plaintext HTTP on port 443, the database is only
a TCP listener, and MLLP is a minimal demonstrator. Record these limits.

## 10. Stop, resume and troubleshoot

- **Stop:** cleanly shut down each Alpine guest (`poweroff` as root) and use
  OPNsense's Halt/Power Off menu. A baseline snapshot taken with guests off can
  help restore a known state after experiments.
- **Resume:** start the firewall, then the clients. Reapply Windows routes after
  a Windows restart. Keep the log receiver running during log-based experiments.
- **Missing host-only adapter / inaccessible GUI:** leave guests off and rerun
  `configure_imported_lab_windows.ps1` with the correct imported directory.
- **SSH refuses a private-key permission:** apply the Windows `icacls` step for
  native Windows SSH; use a copied key under the WSL Linux home with mode 600
  for Ubuntu SSH. Do not use the key directly from `/mnt/c` or `/mnt/d` there.
- **E2/E5 still pass after a rule change:** clear the existing flow's state and
  check rule order in the API/new rule system before recording a conclusion.
- **E8 log missing:** verify the Windows receiver, scoped UDP firewall rule,
  OPNsense remote destination and WSL file link. A timeout alone is not proof
  that a particular policy rule blocked traffic.
- **Readiness fails after an experiment:** remove its temporary GUI rules and
  restore the baseline. `run_firewall_loader.py load --apply` can restore the
  original API-managed lab rows using the bundled runtime YAML, but it does
  not remove unrelated manually added rules or configure IPS/App-ID. Inspect
  those separately, then repeat readiness after restoring the baseline.

## Export verification boundary

`../results/appliance_export.json` records the actual archive size/checksum,
five-machine inventory, manifest verification and VirtualBox import dry run.
The export script verifies the dedicated team SSH key on all five source
guests. A successful import dry run does not prove boot/network compatibility
on another laptop: complete Section 6 on the recipient's machine.

To export a future clean baseline on the source machine, review the default
dry run of `export_lab_appliance.py`, then pass `--export`. It never overwrites
an existing appliance and preserves a 512 MiB workspace free-space reserve.
