---
title: Assurance Check — Host Firewall Default Deny Stance
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - assurance
  - firewall
  - default-deny
---

# Assurance Check — Host Firewall Default Deny Stance

Verifies that Windows Defender Firewall and Linux `nftables`/`iptables` policies enforce a strict default inbound drop stance across all active network profiles.

## PowerShell Audit (Windows)

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    ForEach-Object {
        $Stance = if ($_.DefaultInboundAction -eq "Block") { "[PASS]" } else { "[FAIL]" }
        Write-Host "$Stance Profile: $($_.Name) - Inbound: $($_.DefaultInboundAction) - Enabled: $($_.Enabled)"
    }
```
