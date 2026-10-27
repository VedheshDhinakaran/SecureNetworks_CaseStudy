# Windows is the README's 192.168.90.5 management/bastion host.
# Add only temporary routes for the four isolated lab subnets.
[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$plan = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'results\lab_network_plan.json') -Raw | ConvertFrom-Json
$address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.90.5
$adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceIndex -eq $address.InterfaceIndex }
if ($adapter.InterfaceDescription -notmatch 'VirtualBox.*Host-Only') {
    throw 'The management address is not on the expected VirtualBox host-only adapter.'
}
$prefixes = @()
foreach ($id in @('opt1', 'opt2', 'opt3', 'opt4')) {
    $network = $plan.interfaces.$id
    if ($network.prefix -ne 24) { throw 'Review changed lab prefix before adding host routes.' }
    $octets = $network.address.Split('.')
    $octets[3] = '0'
    $prefixes += ($octets -join '.') + '/24'
}
$records = @()
foreach ($prefix in $prefixes) {
    $existing = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        if (@($existing | Where-Object { $_.NextHop -eq '192.168.90.1' -and $_.InterfaceIndex -eq $address.InterfaceIndex }).Count -ne $existing.Count) {
            throw ('Conflicting existing route; review it manually: ' + $prefix)
        }
        $status = 'already present'
    } elseif ($Apply) {
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $address.InterfaceIndex -NextHop 192.168.90.1 -RouteMetric 5 -PolicyStore ActiveStore | Out-Null
        $status = 'added to ActiveStore; removed by Windows reboot'
    } else {
        $status = 'plan only; add with -Apply in an Administrator terminal'
    }
    Write-Output ($prefix + ' via 192.168.90.1: ' + $status)
    $records += [ordered]@{ prefix = $prefix; gateway = '192.168.90.1'; interface_index = $address.InterfaceIndex; status = $status }
}
if ($Apply) {
    [ordered]@{ recorded_at = [DateTimeOffset]::UtcNow.ToString('o'); persistent = $false; default_route_changed = $false; routes = $records } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'results\host_routes.json') -Encoding UTF8
}
