# Reconnect the five imported guests to the original lab networks on THIS PC.
# Dry run by default. Run -Apply from Administrator PowerShell after OVA import.
[CmdletBinding()]
param(
    [string]$VmDirectory = (Join-Path $env:USERPROFILE 'VirtualBox VMs\CS07'),
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
$executionRoot = Split-Path -Parent $PSScriptRoot
$vmRoot = [IO.Path]::GetFullPath($VmDirectory)
$names = @('opnsense', 'his-vm', 'pump-vm', 'rad-vm', 'vendor-vm')
if (-not (Test-Path -LiteralPath $vbox -PathType Leaf)) { throw 'Install VirtualBox first.' }
function Invoke-VBox {
    param([string[]]$ArgumentList)
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $vbox @ArgumentList 2>&1
        $nativeExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($nativeExit -ne 0) { throw ('VBoxManage failed: ' + ($ArgumentList -join ' ') + "`n" + ($output -join "`n")) }
    $output | ForEach-Object { [string]$_ }
}
foreach ($name in $names) {
    $text = (Invoke-VBox -ArgumentList @('showvminfo', $name, '--machinereadable')) -join "`n"
    $encoded = [regex]::Match($text, '(?m)^CfgFile=(.+)$').Groups[1].Value.Trim()
    if (-not $encoded) { throw ('Cannot read registered VM path: ' + $name) }
    $cfg = [IO.Path]::GetFullPath(($encoded | ConvertFrom-Json))
    $expected = [IO.Path]::GetFullPath((Join-Path (Join-Path $vmRoot $name) ($name + '.vbox')))
    if (-not [string]::Equals($cfg, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Refusing to reconfigure a VM outside the supplied lab directory: ' + $name + '. Check -VmDirectory.')
    }
    if ($Apply -and $text -notmatch '(?m)^VMState="poweroff"') { throw ('Shut down the imported guest first: ' + $name) }
}
$hostIf = $null
$interfaces = (Invoke-VBox -ArgumentList @('list', 'hostonlyifs')) -join "`n"
foreach ($block in ($interfaces -split '(?:\r?\n){2,}')) {
    if ($block -match 'IPAddress:\s+192\.168\.90\.5(?:\s|$)') {
        $hostIf = [regex]::Match($block, '(?m)^Name:\s+(.+)$').Groups[1].Value.Trim()
    }
}
$assigned = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.90.5 -ErrorAction SilentlyContinue)
foreach ($address in $assigned) {
    $adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceIndex -eq $address.InterfaceIndex }
    if ($adapter.InterfaceDescription -notmatch 'VirtualBox.*Host-Only' -or $address.PrefixLength -ne 24) {
        throw '192.168.90.5 is already used by a conflicting interface; resolve that conflict first.'
    }
}
Write-Output ('Imported VM folder: ' + $vmRoot)
Write-Output 'Plan: MGMT host-only 192.168.90.5/24; firewall WAN NAT; four original internal networks.'
Write-Output 'Existing disks, guest addresses, MAC addresses and firewall policy are retained.'
Write-Output 'All five imported VMs must be powered off before -Apply.'
if (-not $Apply) {
    Write-Output 'PLAN ONLY. Run again with -Apply in Administrator PowerShell to reconnect the imported lab.'
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '-Apply requires Administrator PowerShell for host-only networking and lab routes.'
}
if (-not $hostIf) {
    $created = (Invoke-VBox -ArgumentList @('hostonlyif', 'create')) -join "`n"
    $hostIf = [regex]::Match($created, "Interface '(.+?)'").Groups[1].Value
    if (-not $hostIf) { throw ('Could not identify the newly created host-only interface: ' + $created) }
    Invoke-VBox -ArgumentList @('hostonlyif', 'ipconfig', $hostIf, '--ip', '192.168.90.5', '--netmask', '255.255.255.0')
}
Invoke-VBox -ArgumentList @('modifyvm', 'opnsense', '--nic1', 'nat', '--nic2', 'hostonly', '--host-only-adapter2', $hostIf,
    '--nic3', 'intnet', '--intnet3', 'sjv-his', '--nic4', 'intnet', '--intnet4', 'sjv-devices',
    '--nic5', 'intnet', '--intnet5', 'sjv-radiology', '--nic6', 'intnet', '--intnet6', 'sjv-vendor')
foreach ($i in 1..6) {
    Invoke-VBox -ArgumentList @('modifyvm', 'opnsense', ("--nic-type$i"), '82540EM', ("--cable-connected$i"), 'on')
}
foreach ($i in 3..6) { Invoke-VBox -ArgumentList @('modifyvm', 'opnsense', ("--nic-promisc$i"), 'allow-all') }
$networks = @{ 'his-vm' = 'sjv-his'; 'pump-vm' = 'sjv-devices'; 'rad-vm' = 'sjv-radiology'; 'vendor-vm' = 'sjv-vendor' }
foreach ($name in $networks.Keys) {
    Invoke-VBox -ArgumentList @('modifyvm', $name, '--nic1', 'intnet', '--intnet1', $networks[$name], '--nic-type1', '82540EM', '--cable-connected1', 'on')
}
& (Join-Path $executionRoot 'configure_host_routes.ps1') -Apply
Write-Output 'Imported lab networking configured. Start opnsense first, then the four Alpine VMs; follow appliance/README.md.'
