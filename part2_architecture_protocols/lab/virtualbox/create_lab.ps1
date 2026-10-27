# =====================================================================
#  Build the CS07 lab in VirtualBox on Windows (PowerShell 5+)
#  Usage:
#    .\create_lab.ps1 -OpnIso C:\iso\OPNsense-25.x-dvd-amd64.iso -AlpineIso C:\iso\alpine-virt-3.20.x-x86_64.iso
# =====================================================================
param(
  [Parameter(Mandatory = $true)][string]$OpnIso,
  [Parameter(Mandatory = $true)][string]$AlpineIso
)
$ErrorActionPreference = "Stop"
$vbox = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $vbox)) { throw "VBoxManage.exe not found at $vbox" }
foreach ($f in @($OpnIso, $AlpineIso)) { if (-not (Test-Path $f)) { throw "Not found: $f" } }

$vmDir = ((& $vbox list systemproperties) | Select-String "Default machine folder:").ToString().Split(":", 2)[1].Trim()
$existing = & $vbox list vms

# MGMT host-only adapter at 192.168.90.5
$hostIf = $null
$ifs = (& $vbox list hostonlyifs) -join "`n"
foreach ($block in ($ifs -split "`n`n")) {
  if ($block -match "IPAddress:\s+192\.168\.90\.5") { $hostIf = ([regex]::Match($block, "Name:\s+(.+)")).Groups[1].Value.Trim() }
}
if (-not $hostIf) {
  $out = & $vbox hostonlyif create
  $hostIf = ([regex]::Match(($out -join " "), "Interface '(.+?)'")).Groups[1].Value
  & $vbox hostonlyif ipconfig "$hostIf" --ip 192.168.90.5 --netmask 255.255.255.0
}
Write-Host "[+] MGMT host-only adapter: $hostIf"

function New-LabVm($name, $ostype, $ram, $cpus, $diskMb, $iso) {
  if ($existing -match "`"$name`"") { Write-Host "[=] $name exists, skipping"; return $false }
  Write-Host "[+] creating $name"
  & $vbox createvm --name $name --ostype $ostype --register | Out-Null
  & $vbox modifyvm $name --memory $ram --cpus $cpus --boot1 disk --boot2 dvd --audio-enabled off --usb off
  $vdi = Join-Path $vmDir "$name\$name.vdi"
  & $vbox createmedium disk --filename $vdi --size $diskMb | Out-Null
  & $vbox storagectl $name --name SATA --add sata --controller IntelAhci
  & $vbox storageattach $name --storagectl SATA --port 0 --device 0 --type hdd --medium $vdi
  & $vbox storageattach $name --storagectl SATA --port 1 --device 0 --type dvddrive --medium $iso
  return $true
}

if (New-LabVm "opnsense" "FreeBSD_64" 4096 2 20480 $OpnIso) {
  & $vbox modifyvm opnsense --nic1 nat --nic2 hostonly --host-only-adapter2 "$hostIf" `
      --nic3 intnet --intnet3 sjv-his --nic4 intnet --intnet4 sjv-devices `
      --nic5 intnet --intnet5 sjv-radiology --nic6 intnet --intnet6 sjv-vendor
  1..6 | ForEach-Object { & $vbox modifyvm opnsense "--nic-type$_" 82540EM }
  3..6 | ForEach-Object { & $vbox modifyvm opnsense "--nic-promisc$_" allow-all }
}

$zones = [ordered]@{ "his-vm" = "sjv-his"; "pump-vm" = "sjv-devices"; "rad-vm" = "sjv-radiology"; "vendor-vm" = "sjv-vendor" }
foreach ($vm in $zones.Keys) {
  if (New-LabVm $vm "Linux_64" 512 1 2048 $AlpineIso) {
    & $vbox modifyvm $vm --nic1 intnet --intnet1 $zones[$vm] --nic-type1 82540EM
  }
}
Write-Host "`nDone. Follow the next steps printed in create_lab.sh / the README."
