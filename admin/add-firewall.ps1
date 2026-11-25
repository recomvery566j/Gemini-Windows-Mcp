# pc-work-mcp inbound firewall rule (run as Administrator)
param(
    [int]$Port = 15672,
    [string]$RemoteAddress = 'LocalSubnet'
)

$name = "pc-work-mcp $Port"
$existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "rule already exists: $name"
} else {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP `
        -LocalPort $Port -Action Allow -Profile Private,Domain -RemoteAddress $RemoteAddress | Out-Null
    Write-Host "added rule: $name (TCP $Port, remote=$RemoteAddress)"
}
Get-NetFirewallRule -DisplayName $name | Format-Table DisplayName,Enabled,Direction,Action -AutoSize
