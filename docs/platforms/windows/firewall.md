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

Windows Defender Firewall with Advanced Security provides host-based packet filtering and containment capabilities across Domain, Private, and Public network profiles. Follow the 5-stage systematic progression: verify the firewall service and profile states, identify policy locations across GPO and registry, inspect active allow/block rules, configure audit logging, and implement emergency containment controls.

## 1. Check Process, Service & Socket State

Verify that the Windows Firewall service (`mpssvc`) is active and inspect the current operational state of each firewall profile:

```powershell
# Verify the underlying Windows Firewall service is running
Get-Service -Name mpssvc | Select-Object Name, Status, StartType, DisplayName

# Inspect active firewall profiles and default traffic actions
Get-NetFirewallProfile -PolicyStore ActiveStore |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName
```

```text
netsh advfirewall show allprofiles
```

`DefaultInboundAction : NotConfigured` means the built-in default applies (block inbound). A profile can be enabled locally but overridden by GPO — `-PolicyStore ActiveStore` displays the effective runtime result.

## 2. Known Locations & Configuration Roots

### Where is the setting?

Firewall configurations can be applied locally, via GPO, or through Intune/MDM. Use this reference to locate or manage settings across management tiers:

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

| Location | Path / Console | Purpose |
| :--- | :--- | :--- |
| **Advanced Management** | `wf.msc` | MMC console for detailed inbound/outbound rules |
| **Service Root** | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess` | Core firewall service configuration |
| **GPO Registry Key** | `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall` | Group Policy enforced policy overrides |
| **Log Target** | `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log` | Default dropped/allowed traffic log |

## 3. Configuration Inspection & Rule Auditing

### List enabled inbound allow rules with ports

Audit all active inbound listening hole punches and applications allowed through the perimeter:

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

**What to look for:** rules allowing `Any` port to a binary located in user-writable paths (`C:\Users\`, `C:\ProgramData\`, `C:\Temp\`), broad RDP/SMB/WinRM rules open across Public profiles, and recently created rules with ambiguous names.

## 4. Operational Diagnostics & Change Logging

### Enable firewall logging

Capture dropped packets to diagnose unauthorized connection attempts or verify blocking actions:

```powershell
Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384
```

Default log path: `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`.

### Detect firewall changes

Monitor the Windows Firewall event channel for tampering and unauthorized rule creation:

Log: `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -MaxEvents 50 |
    Select-Object TimeCreated, Id, Message
```

On Windows 10 / Server 2016–2019 rule changes are logged as **2004** (added), **2005** (modified), **2006** (deleted). Newer Windows 11 / Server 2022+ builds log different event IDs for the same actions — review the log on your build rather than filtering on a fixed ID.

## 5. Hardening & Containment Controls

### Block an IP during containment

Isolate malicious external C2 infrastructure or restrict compromised internal hosts during active incident triage:

```powershell
New-NetFirewallRule -DisplayName 'IR-Block-<TARGET_IP>' -Direction Outbound -RemoteAddress '<TARGET_IP>' -Action Block
New-NetFirewallRule -DisplayName 'IR-Block-<TARGET_IP>-In' -Direction Inbound -RemoteAddress '<TARGET_IP>' -Action Block
```

Remove containment rules following resolution:

```powershell
Remove-NetFirewallRule -DisplayName 'IR-Block-<TARGET_IP>*'
```

**Operational rule:** Always use a consistent `IR-` prefix for containment rules so they are readily identifiable and audited. Block rules take precedence over allow rules. If a GPO sets **Apply local firewall rules = No**, locally created rules (including these) are ignored — contain through GPO or your EDR's network isolation instead.

## Related

- [Windows Networking](networking.md)
- [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md)
- [Linux firewall commands](../linux/networking.md#firewall-rules)

## Sources

- [NetSecurity module](https://learn.microsoft.com/powershell/module/netsecurity/)
- [Configure Windows Firewall logging](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure-logging)
