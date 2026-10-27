# Read the real host/VM state and save it in Part II. No credentials are read.
[CmdletBinding()]
param([string]$Stage = 'VM hardware inspection; operating-system and firewall validation pending')
$ErrorActionPreference = 'Stop'
$vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
$part2Now = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow, 'India Standard Time')
$computer = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$machines = @()
if (Test-Path -LiteralPath $vbox -PathType Leaf) {
    $version = (& $vbox --version | Out-String).Trim()
    $registered = (& $vbox list vms | Out-String)
    foreach ($name in @('opnsense', 'his-vm', 'pump-vm', 'rad-vm', 'vendor-vm')) {
        if ($registered -notmatch ('"' + [regex]::Escape($name) + '"')) {
            $machines += [ordered]@{ name = $name; registered = $false }
            continue
        }
        $details = & $vbox showvminfo $name --machinereadable
        if ($LASTEXITCODE -ne 0) { throw ('Cannot inspect ' + $name) }
        $fields = [ordered]@{ name = $name; registered = $true }
        foreach ($line in $details) {
            if ($line -match '^(VMState|memory|cpus|ostype|firmware|nic[1-8]|intnet[1-8]|hostonlyadapter[1-8]|CfgFile)=(.*)$') {
                $fields[$Matches[1]] = $Matches[2].Trim('"')
            }
        }
        $machines += $fields
    }
} else {
    $version = 'not installed'
}
$proof = Get-ChildItem -Path (Join-Path $PSScriptRoot 'results\readiness_*\summary.json') -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
$readiness = if ($proof) { Get-Content -LiteralPath $proof.FullName -Raw | ConvertFrom-Json } else { $null }
$verified = $readiness -and $readiness.passed -and $readiness.policy_rule_count -eq 18 -and $readiness.temporary_setup_rule_count -eq 0
$report = [ordered]@{
    recorded_at = $part2Now.ToString('o')
    stage = $Stage
    firewall_lab_verified = [bool]$verified
    verification_scope = 'Part II lab readiness; not completion of joint E1-E8, IPS/App-ID, HA or physical-switch controls'
    readiness_evidence = if ($proof) { 'results/' + $proof.Directory.Name + '/summary.json' } else { $null }
    host = [ordered]@{
        manufacturer = $computer.Manufacturer; model = $computer.Model
        ram_bytes = $computer.TotalPhysicalMemory; cpu = $cpu.Name
        os = $os.Caption; os_version = $os.Version
    }
    virtualbox_version = $version
    machines = $machines
    interpretation = 'Registered/running VMs do not establish installed operating systems, loaded firewall rules or successful experiment results.'
}
$out = Join-Path $PSScriptRoot 'results\lab_status.json'
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $out -Encoding UTF8
Write-Output ('Saved: ' + $out)
Write-Output ($machines | ConvertTo-Json -Depth 4)
