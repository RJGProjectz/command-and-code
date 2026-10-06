---
title: Assurance Check — Azure Network Security Group Compliance
type: entry
platforms:
  - Azure
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - assurance
  - azure
  - nsg
  - compliance
---

# Assurance Check — Azure Network Security Group Compliance

Verifies that no Azure Network Security Groups (NSGs) allow unrestricted ingress (`0.0.0.0/0` or `*`) across sensitive administration ports (SSH 22, RDP 3389, WinRM 5985/5986).

## PowerShell Compliance Audit

```powershell
$ViolationList = @()
$NSGs = Get-AzNetworkSecurityGroup

foreach ($nsg in $NSGs) {
    $ExposedRules = $nsg.SecurityRules | Where-Object {
        $_.Access -eq "Allow" -and
        $_.Direction -eq "Inbound" -and
        ($_.SourceAddressPrefix -contains "*" -or $_.SourceAddressPrefix -contains "Internet" -or $_.SourceAddressPrefix -contains "0.0.0.0/0") -and
        ($_.DestinationPortRange -contains "22" -or $_.DestinationPortRange -contains "3389" -or $_.DestinationPortRange -contains "*")
    }
    if ($ExposedRules) {
        $ViolationList += [PSCustomObject]@{
            NSGName       = $nsg.Name
            ResourceGroup = $nsg.ResourceGroupName
            Rules         = ($ExposedRules.Name -join ', ')
        }
    }
}

if ($ViolationList.Count -gt 0) {
    Write-Warning "[FAIL] Exposed management ports found in $($ViolationList.Count) NSGs!"
    $ViolationList | Format-Table -AutoSize
} else {
    Write-Host "[PASS] All Azure NSG administrative ingress rules are compliant." -ForegroundColor Green
}
```
