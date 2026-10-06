---
title: Windows Firewall
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Administration, Hardening, Incident Response, Troubleshooting]
category: Firewall
tags: [firewall, gpo, containment, block ip, configuration]
aliases: [windows defender firewall, netsh advfirewall, block an IP, firewall rules, firewall logging]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Firewall

## Where is the setting?

=== "GUI"

    ```text
    Windows Security → Firewall & network protection
    Advanced rules: wf.msc (Windows Defender Firewall with Advanced Security)
    ```

=== "PowerShell"

    ```powershell
    Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName
    ```

=== "CLI"

    ```text
    netsh advfirewall show allprofiles
    ```

=== "GPO"

    ```text
    Computer Configuration
    → Policies
    → Windows Settings
    → Security Settings
    → Windows Defender Firewall with Advanced Security
    ```

    Legacy (pre-Vista style) settings are also under
    `Computer Configuration → Administrative Templates → Network → Network Connections → Windows Defender Firewall`.

=== "Registry"

    ```text
    Policy (GPO-applied):  HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall
    Local configuration:   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
    ```

`DefaultInboundAction : NotConfigured` means the built-in default applies (block inbound). A profile can be enabled locally but overridden by GPO — `Get-NetFirewallProfile -PolicyStore ActiveStore` shows the effective result.

## List enabled inbound allow rules with ports

```powershell
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    ForEach-Object {
        $port = $_ | Get-NetFirewallPortFilter
        $app  = $_ | Get-NetFirewallApplicationFilter
        [pscustomobject]@{
            Name      = $_.DisplayName
            Profile   = $_.Profile
            Protocol  = $port.Protocol
            LocalPort = ($port.LocalPort -join ',')
            Program   = $app.Program
        }
    } | Sort-Object Name
```

**What to look for:** rules allowing `Any` port to a program in a user-writable path, broad RDP/SMB/WinRM allows on workstations, rules with generic names created recently.

## Block an IP during containment

```powershell
New-NetFirewallRule -DisplayName 'IR-Block-<TARGET_IP>' -Direction Outbound -RemoteAddress '<TARGET_IP>' -Action Block
New-NetFirewallRule -DisplayName 'IR-Block-<TARGET_IP>-In' -Direction Inbound -RemoteAddress '<TARGET_IP>' -Action Block
```

Remove later with `Remove-NetFirewallRule -DisplayName 'IR-Block-<TARGET_IP>*'`. Use a consistent `IR-` prefix so containment rules are easy to find and clean up. Block rules take precedence over allow rules. If a GPO sets **Apply local firewall rules = No**, locally created rules (including these) are ignored — contain through GPO or your EDR's network isolation instead.

## Enable firewall logging

```powershell
Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384
```

Default log path: `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`.

## Detect firewall changes

Log: `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -MaxEvents 50 |
    Select-Object TimeCreated, Id, Message
```

On Windows 10 / Server 2016–2019 rule changes are logged as **2004** (added), **2005** (modified), **2006** (deleted). Newer Windows 11 / Server 2022+ builds log different event IDs for the same actions — review the log on your build rather than filtering on a fixed ID.

## Related

- [Windows Networking](networking.md)
- [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md)
- [Linux firewall commands](../linux/networking.md#firewall-rules)

## Sources

- [NetSecurity module](https://learn.microsoft.com/powershell/module/netsecurity/)
- [Configure Windows Firewall logging](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure-logging)
