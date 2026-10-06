---
title: Intune
platforms: [Microsoft 365, Intune, Windows]
languages: [PowerShell, Windows CLI]
tasks: [Administration, Troubleshooting, Incident Response]
category: Device Management
tags: [intune, mdm, dsregcmd, managed devices, remote actions, ime logs]
aliases: [dsregcmd status, intune sync, intune logs, managed device lookup, remote wipe]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Intune

## Check device join and enrollment state

On the device:

```text
dsregcmd /status
```

| Field | Meaning |
| --- | --- |
| `AzureAdJoined : YES` | Entra-joined |
| `DomainJoined : YES` + `AzureAdJoined : YES` | Hybrid joined |
| `AzureAdPrt : YES` | Device holds a Primary Refresh Token (SSO works) |
| `MdmUrl` | Populated when MDM-enrolled |

## Client logs

| Source | Location |
| --- | --- |
| Intune Management Extension (Win32 apps, scripts, remediations) | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\` |
| MDM event log | `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin` |
| MDM diagnostics report | Settings → Accounts → Access work or school → *Export your management log files* |

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 50 |
    Where-Object LevelDisplayName -in 'Error', 'Warning' |
    Select-Object TimeCreated, Id, Message
```

## Trigger a sync from the device

Settings → Accounts → Access work or school → select the account → **Info** → **Sync**.

## Find a managed device (Graph PowerShell)

```powershell
Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All'
Get-MgDeviceManagementManagedDevice -Filter "deviceName eq 'LAPTOP-042'" |
    Select-Object DeviceName, UserPrincipalName, OperatingSystem, OSVersion, ComplianceState, LastSyncDateTime, Id
```

## Remote actions (Graph API)

Require `DeviceManagementManagedDevices.PrivilegedOperations.All`.

```text
POST https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{id}/syncDevice
POST https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{id}/rebootNow
POST https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{id}/windowsDefenderScan
     body: { "quickScan": true }
POST https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{id}/retire
POST https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{id}/wipe
```

```powershell
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/syncDevice"
```

!!! danger "Wipe is destructive"
    `wipe` factory-resets the device and destroys forensic evidence. For incident response, isolate through Defender for Endpoint first and collect evidence.

## Related

- [Defender XDR](defender.md)
- [Entra ID](entra.md)

## Sources

- [dsregcmd](https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd)
- [managedDevice resource](https://learn.microsoft.com/graph/api/resources/intune-devices-manageddevice)
- [Intune Management Extension logs](https://learn.microsoft.com/mem/intune/apps/intune-management-extension)
