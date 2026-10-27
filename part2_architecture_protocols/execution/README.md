# Part II implementation and evidence

Owner: Debapriya Kundu (CSE23115).

This directory contains the work used to put the existing Part II design into
practice. The original source files, network objects and teammates' folders
are preserved. `baseline_sha256.json` records the original tracked files.

| Location | Purpose |
|---|---|
| `run_offline_checks.py` | Runs the existing tests and validation commands; saves their actual output |
| `fetch_lab_media.py` | Downloads official installer media and verifies publisher SHA256 checksums |
| `create_lab_windows.ps1` | Builds the original five-VM topology in a configurable local disk folder; dry run by default |
| `verify_local_services.py` | Runs the original services on loopback and checks HTTP, TCP and HL7/MLLP behaviour |
| `record_lab_status.ps1` | Records the actual host and VM hardware state without reading credentials |
| `configure_host_routes.ps1` | Adds four temporary Windows routes through the lab firewall; administrator rights required |
| `lab_console.py`, `lab_ssh.py` | Access only the named lab VMs; console debug captures are ignored by default |
| `run_firewall_loader.py` | Calls the original Part III loader with interface-search compatibility for OPNsense 25.7 |
| `verify_lab_readiness.py`, `run_lab_readiness.py` | Check real guest/services/allowed and blocked flows; retain bounded PF evidence |
| `setup/` | Interface, installer and source-binding helpers; recovery steps for failures actually encountered |
| `build_part2_report.py` | Builds a detailed validation record and places a concise Section 7.5 inside Part II of the supplied report |
| `prepare_git_handoff.py` | Verifies source hashes, size, scope and private exclusions; archives redundant debug output with `--tidy` |
| `results/` | Dated output, exit codes and manifests from checks actually run |
| `report/` | Part II implementation record; includes measured results and explicitly pending lab work |
| `.local/` | Ignored downloads, temporary test directories and local working files |

Run from the repository root:

```powershell
python -B part2_architecture_protocols/execution/run_offline_checks.py
python -B part2_architecture_protocols/execution/fetch_lab_media.py
python -B part2_architecture_protocols/execution/verify_local_services.py
.\part2_architecture_protocols\execution\create_lab_windows.ps1
# After reviewing the plan, installing VirtualBox and downloading media:
.\part2_architecture_protocols\execution\create_lab_windows.ps1 -VmDirectory 'C:\MyLabDisks\CS07' -Create
```

Offline checks and local service checks are not evidence that segmentation,
IPS or application identification work on OPNsense. Those require the actual
isolated VM lab. Expected results are never copied into observed-results cells.

The supplied design uses OPNsense 25.x and Alpine 3.20. The downloader pins
OPNsense 25.7 and Alpine 3.20.10 for compatibility with that design. Record
the versions actually installed; do not describe these archived releases as
current production recommendations. VirtualBox media is the base package;
the separately licensed Extension Pack is not required by this lab.

The Windows host has approximately 16 GB RAM. At the preflight check D: had
about 6 GB free and C: about 65 GB free, so this machine uses C: for VM disks.
The builder defaults to `<your user profile>\VirtualBox VMs\CS07`; teammates
can set `-VmDirectory` to any suitable local drive. No global VirtualBox
storage preference is changed. Share the source, sanitised configuration,
results and report through Git. VM disks and ISO downloads are local working
data. A separately shared OVA can be used if a teammate wants prebuilt VMs.

Part II owns the lab foundation and Chapters 5–7 plus Sections 11.2–11.4.
Firewall rules remain owned by Part III. E1–E8 and their observed-results
tables remain shared work led by Part IV. VirtualBox does not demonstrate
physical switch NAC/PVLAN enforcement or HA failover.

## Current completion boundary

The successful offline run is under `results/offline_20261027T175111/`:
all 42 existing tests passed, including the 9 Part II tests. The 30 policy
probes and 18-rule subset checks passed. The original service processes
passed six loopback integration checks under `results/local_services_20261027T175339/`.

Part II's lab foundation is complete. VirtualBox 7.2.22, OPNsense 25.7 and
all four Alpine 3.20.10 guests are installed. Every supplied zone setup
script completed successfully. All five VMs retained their configuration
after reboot. The final firewall has exactly 18 policy rules, zero temporary
setup rules, and no running temporary package server.

`results/readiness_20261027T222816/` records **35 passing real readiness
checks**, including seven denied flows corroborated by the PF packet log.
The capture is about 22 KiB. Allowed DNS/TCP/UDP, NTP, HTTP, SSH and HL7/AA
flows worked; vendor public HTTP/HTTPS worked; prohibited internal and pump
web connections were blocked. The actual internal NTP response was stratum
3 with leap status 0. See `summary.json`, per-host records and the decoded
log. Successful original setup output is under `results/setup/`.

The main report contains 40 pages. Section 7.5, on PDF page 20 (printed page
17), presents two results tables below Table 7.1 in Part II: Table 7.2 covers
software and policy checks; Table 7.3 breaks down actual VM readiness checks
by lab role. The seven logged block confirmations are included in the 35 checks.
The former three-page end appendix is removed. `report/section_7_5.md` holds
the exact added text. The detailed `report/part2_implementation_record.docx`
is editable; Markdown and standalone PDF versions are provided too. E1–E8 Observed cells remain
the team's shared work. These readiness checks do not establish App-ID,
Suricata IPS, HA or physical-switch NAC/PVLAN enforcement.

The original assignment does not mandate a particular VM platform. The
VirtualBox/OPNsense procedure is the existing team's chosen demonstration.
Using the Python simulator alone would require revising the report's lab
claims and would leave deployed firewall behaviour unverified.

## Using the completed lab on this laptop

The local disks are in `C:\Users\debap\VirtualBox VMs\CS07`. Keep them out
of Git. Use the existing VM definitions; do not run `-Create` again.

```powershell
# From the repository root. Starting an already running VM is harmless.
'opnsense','his-vm','pump-vm','rad-vm','vendor-vm' | ForEach-Object {
    python -B part2_architecture_protocols/execution/lab_console.py $_ --start --wait 5
}
# Only after a Windows reboot, from an Administrator PowerShell:
.\part2_architecture_protocols\execution\configure_host_routes.ps1 -Apply

# Allow OPNsense to finish booting, then inspect or repeat readiness checks:
python -B part2_architecture_protocols/execution/run_firewall_loader.py audit
python -B part2_architecture_protocols/execution/run_lab_readiness.py --run
```

The four Windows routes use only the original lab subnets and next hop
192.168.90.1 on the VirtualBox host-only adapter. They are nonpersistent;
the normal internet/default route is unchanged. SSH and API credentials
stay in `.local/`; generate separate credentials on a teammate's machine.

## Rebuilding without changing the original project

1. Follow the parent README's OS-install steps using the verified media and
   original five-VM topology. In the OPNsense UFS installer select **ada0,
   the 20 GB hard disk**, rather than cd0. Configure em0 as NAT/WAN, em1 as
   MGMT, and em2–em5 as HIS/DEVICES/RADIOLOGY/VENDOR. The exported plan is in
   `results/lab_network_plan.json`; regenerate it with `setup/export_lab_plan.py`.
2. Generate a private Ed25519 key at `.local/ssh/lab_admin` with OpenSSH
   ssh-keygen, and install its public `.pub` key for the lab guests. Enable
   root SSH on the isolated firewall. API setup is provided by
   `setup_firewall_api.py --create-key`; its factory-password default can be
   overridden with `OPN_BOOTSTRAP_PASSWORD`. Keys are never shared in Git.
3. Run `setup/seed_firewall_aliases.py`, then
   `run_firewall_loader.py load --apply`. It uses the original policy with
   an equivalent named alias for ports 80 and 443. Use
   `run_firewall_loader.py setup-on --apply` only while installing packages.
4. Install Alpine with `setup-alpine`, copy the original `lab/` directory to
   `/opt/sjv/lab`, and run the matching `hosts/setup_*.sh`, as the parent
   README specifies. Normalize CRLF to LF in guest shell copies only. The
   four answers and installer wrapper from `setup/prepare_alpine_install.py`
   can automate this on the newly created blank 2 GB disks.
5. The optional bootstrap files can be copied to firewall `/tmp/http` with
   `lab_ssh.py opnsense --upload ... --destination /tmp/`. Start their server
   inside that firewall with `daemon -f -p /tmp/cs07-bootstrap.pid -o
   /tmp/cs07-bootstrap.log /usr/local/bin/python3.11 -m http.server 8081
   --bind 0.0.0.0 --directory /tmp/http`. On each guest, fetch
   `http://<its gateway>:8081/run_zone_setup.sh` and run it as root. This
   wrapper executes the unchanged original host script and saves its log.
6. On HIS, stop dnsmasq/chronyd before the initial network reconfiguration
   to avoid the observed OpenRC restart race. The wrapper does this. After
   host setup, apply `setup/configure_his_bindings.sh` on HIS so outbound
   DNS and NTP use .53 and .57, matching H-07/H-06. The repository's original
   host scripts are unchanged. Their deployed shell copies differ only in
   line endings, recorded in `results/guest_line_endings.json`.
7. If guest downloads fail, `setup/fetch_bootstrap_packages.py --build-cache`
   can cache the exact dependencies from a working HIS package inventory.
   Serve `.local/bootstrap/http/apk` temporarily from the same firewall;
   Alpine validates the original signed indexes and packages. The wrapper
   restores original repository settings after setup. Recovery of this
   machine's interrupted radiology install is recorded in
   `setup/resume_radiology_install.sh`; it checks the VM/disk before acting.
8. Detach the installer ISOs only after a normal guest shutdown. Stop the
   temporary server with `pkill -F /tmp/cs07-bootstrap.pid` on OPNsense,
   then run `run_firewall_loader.py setup-off --apply`. Reboot the configured
   VMs, check addresses, and run `run_lab_readiness.py --run`. It refuses
   temporary rules and clears old zone states before capturing real flows.

The API adaptations are confined to this Part II execution layer. In
OPNsense 25.7, a missing alias returns `[]`, comma-separated destination
ports require a port alias, and rule searches require an interface to see
per-interface rules. The wrapper handles these without changing Part III.
All 129 original tracked files retain their baseline SHA256 hashes.

## Updating the report and preparing Git

```powershell
python -B part2_architecture_protocols/execution/build_part2_report.py --update-main-report
python -B part2_architecture_protocols/execution/prepare_git_handoff.py --tidy
```

The report builder preserves the input PDF in ignored storage. It adds
Section 7.5 only in the blank area of original PDF page 20 and verifies that
all original text remains, the other 39 page content streams are identical,
and the original page labels and bookmarks are retained. Rebuilding starts
from the original, so it removes the former end appendix and does not repeat
the new section. Chapter 11 remains the implementation procedure and the
Part IV experiments remain separate from these readiness results.
For a fresh Python environment install `requirements-report.txt` into
`execution/.local/python` with pip's `--target` option.

`results/git_handoff.json` records actual Git-eligible size, original hashes,
scope and private exclusions. ISO/installer downloads, VM disks, package
caches, private keys, API credentials and redundant debug screenshots are
excluded. The script also checks that actual secret values do not appear
in eligible files. It does not stage, commit or push anything. Share these
scripts, compact evidence and the report; teammates rebuild their local VMs.
