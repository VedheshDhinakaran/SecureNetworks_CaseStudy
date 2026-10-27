# Builds the SAME five-VM topology as ../lab/virtualbox/create_lab.ps1.
# Dry run by default. -Create performs creation; existing VMs are never replaced.
[CmdletBinding()]
param(
    [string]$VmDirectory = (Join-Path $env:USERPROFILE 'VirtualBox VMs\CS07'),
    [string]$OpnIso = (Join-Path $PSScriptRoot '.local\media\OPNsense-25.7-dvd-amd64.iso'),
    [string]$AlpineIso = (Join-Path $PSScriptRoot '.local\media\alpine-virt-3.20.10-x86_64.iso'),
    [switch]$Create
)
$ErrorActionPreference = 'Stop'
$vmRoot = [IO.Path]::GetFullPath($VmDirectory)
$vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
$definitions = @(
    @{ Name = 'opnsense'; Os = 'FreeBSD_64'; Ram = 4096; Cpu = 2; Disk = 20480; Iso = $OpnIso; Net = $null },
    @{ Name = 'his-vm'; Os = 'Linux_64'; Ram = 512; Cpu = 1; Disk = 2048; Iso = $AlpineIso; Net = 'sjv-his' },
    @{ Name = 'pump-vm'; Os = 'Linux_64'; Ram = 512; Cpu = 1; Disk = 2048; Iso = $AlpineIso; Net = 'sjv-devices' },
    @{ Name = 'rad-vm'; Os = 'Linux_64'; Ram = 512; Cpu = 1; Disk = 2048; Iso = $AlpineIso; Net = 'sjv-radiology' },
    @{ Name = 'vendor-vm'; Os = 'Linux_64'; Ram = 512; Cpu = 1; Disk = 2048; Iso = $AlpineIso; Net = 'sjv-vendor' }
)
Write-Output ('VM disk folder: ' + $vmRoot)
Write-Output '6 GB total guest RAM; dynamically allocated disks with 28 GB combined virtual capacity.'
$definitions | ForEach-Object {
    Write-Output ('{0}: {1} MB RAM, {2} CPU, {3} MB disk, ISO {4}' -f $_.Name, $_.Ram, $_.Cpu, $_.Disk, $_.Iso)
}
if (-not $Create) {
    Write-Output 'PLAN ONLY. Add -Create after reviewing the paths and downloading verified media.'
    return
}
if (-not (Test-Path -LiteralPath $vbox -PathType Leaf)) { throw 'Install VirtualBox first.' }
foreach ($iso in @($OpnIso, $AlpineIso)) {
    if (-not (Test-Path -LiteralPath $iso -PathType Leaf)) { throw ('Missing ISO: ' + $iso) }
}
function Invoke-VBox {
    param([string[]]$ArgumentList)
    # VBoxManage writes normal progress to stderr. On Windows PowerShell 5
    # this must not be confused with a failed native process.
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
$existing = (Invoke-VBox -ArgumentList @('list', 'vms')) -join "`n"
foreach ($vm in $definitions) {
    if ($existing -match ('"' + [regex]::Escape($vm.Name) + '"')) {
        throw ('VM name already exists: ' + $vm.Name + '. Inspect it before continuing; this script never replaces VMs.')
    }
    if (Test-Path -LiteralPath (Join-Path $vmRoot $vm.Name)) {
        throw ('VM folder already exists: ' + (Join-Path $vmRoot $vm.Name))
    }
}
$null = New-Item -ItemType Directory -Path $vmRoot -Force
$recordDir = Join-Path $PSScriptRoot ('results\vm_creation_' + (Get-Date -Format 'yyyyMMddTHHmmss'))
$null = New-Item -ItemType Directory -Path $recordDir
Start-Transcript -LiteralPath (Join-Path $recordDir 'creation.txt') | Out-Null
try {
    $hostIf = $null
    $interfaces = (Invoke-VBox -ArgumentList @('list', 'hostonlyifs')) -join "`n"
    foreach ($block in ($interfaces -split '(?:\r?\n){2,}')) {
        if ($block -match 'IPAddress:\s+192\.168\.90\.5(?:\s|$)') {
            $hostIf = [regex]::Match($block, '(?m)^Name:\s+(.+)$').Groups[1].Value.Trim()
        }
    }
    if (-not $hostIf) {
        $created = (Invoke-VBox -ArgumentList @('hostonlyif', 'create')) -join "`n"
        $hostIf = [regex]::Match($created, "Interface '(.+?)'").Groups[1].Value
        if (-not $hostIf) { throw ('Could not read created host-only interface: ' + $created) }
        Invoke-VBox -ArgumentList @('hostonlyif', 'ipconfig', $hostIf, '--ip', '192.168.90.5', '--netmask', '255.255.255.0')
    }
    foreach ($vm in $definitions) {
        $name = $vm.Name
        Invoke-VBox -ArgumentList @('createvm', '--name', $name, '--ostype', $vm.Os, '--basefolder', $vmRoot, '--register')
        Invoke-VBox -ArgumentList @('modifyvm', $name, '--memory', [string]$vm.Ram, '--cpus', [string]$vm.Cpu,
            '--firmware', 'bios', '--boot1', 'disk', '--boot2', 'dvd', '--audio-enabled', 'off', '--usb', 'off')
        $disk = Join-Path (Join-Path $vmRoot $name) ($name + '.vdi')
        Invoke-VBox -ArgumentList @('createmedium', 'disk', '--filename', $disk, '--size', [string]$vm.Disk)
        Invoke-VBox -ArgumentList @('storagectl', $name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci')
        Invoke-VBox -ArgumentList @('storageattach', $name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', $disk)
        Invoke-VBox -ArgumentList @('storageattach', $name, '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'dvddrive', '--medium', $vm.Iso)
        if ($name -eq 'opnsense') {
            Invoke-VBox -ArgumentList @('modifyvm', $name, '--nic1', 'nat', '--nic2', 'hostonly', '--host-only-adapter2', $hostIf,
                '--nic3', 'intnet', '--intnet3', 'sjv-his', '--nic4', 'intnet', '--intnet4', 'sjv-devices',
                '--nic5', 'intnet', '--intnet5', 'sjv-radiology', '--nic6', 'intnet', '--intnet6', 'sjv-vendor')
            foreach ($i in 1..6) { Invoke-VBox -ArgumentList @('modifyvm', $name, "--nic-type$i", '82540EM') }
            foreach ($i in 3..6) { Invoke-VBox -ArgumentList @('modifyvm', $name, "--nic-promisc$i", 'allow-all') }
        } else {
            Invoke-VBox -ArgumentList @('modifyvm', $name, '--nic1', 'intnet', '--intnet1', $vm.Net, '--nic-type1', '82540EM')
        }
        Invoke-VBox -ArgumentList @('showvminfo', $name, '--machinereadable') |
            Set-Content -LiteralPath (Join-Path $recordDir ($name + '_hardware.txt')) -Encoding UTF8
    }
    Write-Output 'VM hardware created. Operating systems and services still require installation.'
} finally {
    Stop-Transcript | Out-Null
}
