---
title: Mobile Device and Application Security
type: concept
platforms: [Intune, Microsoft 365]
languages: [PowerShell, KQL]
tasks: [Hardening, Assurance, Investigation]
category: Endpoint Security
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, mobile, mdm, intune, masvs]
aliases: [Mobile Application Security, Mobile Security Tools]
difficulty: intermediate
verified: false
---

# Mobile Device and Application Security
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** phones hold mail, MFA and company data, so they need management (MDM/MAM), app vetting and the same attention as laptops.

## What it is

| Risk | Example |
| :--- | :--- |
| Malicious or over-privileged apps | sideloaded APKs, fake banking apps, apps reading SMS codes |
| Phishing on mobile | [smishing](social-engineering.md), QR-code phishing — small screens hide URLs |
| Lost / stolen devices | unencrypted or unmanaged devices with mail and files |
| Jailbreak / root | disables the platform sandbox and security updates |
| Insecure apps you build | data stored in clear, weak TLS validation, hard-coded keys (OWASP Mobile Top 10) |
| Targeted spyware | zero-click exploits ([malware](malware-types-analysis.md)) |

**Controls:** MDM (device compliance: OS version, encryption, passcode, not jailbroken), MAM / app-protection policies
(company data only in managed apps, no copy-paste to personal apps), [Conditional Access](../../platforms/microsoft-365/conditional-access.md)
requiring a compliant device, Mobile Threat Defense, timely OS updates.

**Testing your own apps:** OWASP MASVS (requirements) and MASTG (testing guide); tools such as MobSF (static/dynamic
analysis), Frida and objection (runtime instrumentation) in a test environment. Enterprise guidance: NIST SP 800-124.

## How it works

Enrol → assess compliance → grant access only to compliant devices → protect data inside managed apps → wipe company data
(selective wipe) when a device is lost or a user leaves.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [Mobile matrix](https://attack.mitre.org/matrices/mobile/) — e.g. [T1660](https://attack.mitre.org/techniques/T1660/) Phishing, [T1404](https://attack.mitre.org/techniques/T1404/) Exploitation for Privilege Escalation |
| **What it leads to** | MFA codes and mail stolen from phones, data leaking to personal apps |
| **Where defenders meet it** | Intune non-compliance, risky sign-ins from unmanaged devices, lost-device tickets |

## Do it

```powershell
# Managed devices that are non-compliant or jailbroken (Microsoft Graph PowerShell)
Get-MgDeviceManagementManagedDevice -All |
    Where-Object -FilterScript { $_.ComplianceState -ne 'compliant' -or $_.JailBroken -eq 'True' } |
    Select-Object -Property DeviceName, OperatingSystem, OsVersion, ComplianceState, JailBroken, UserPrincipalName
```

```kql
// Sign-ins from mobile platforms on unmanaged devices
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == 0
| extend OS = tostring(DeviceDetail.operatingSystem), Managed = tostring(DeviceDetail.isManaged)
| where OS in~ ("Android", "iOS") and Managed != "true"
| summarize SignIns = count() by UserPrincipalName, OS, AppDisplayName
```

## See it

| Source | What you see |
| :--- | :--- |
| Intune device inventory | compliance state, OS version, jailbreak status, encryption |
| Entra `SigninLogs` | `DeviceDetail.isCompliant` / `isManaged` per sign-in |
| MTD / Defender for Endpoint mobile | malicious apps, phishing link blocks |

## Detect it

- Platform: [Intune](../../platforms/microsoft-365/intune.md) · [Conditional Access](../../platforms/microsoft-365/conditional-access.md)
- Forensics: [Digital forensics](digital-forensics.md) — mobile extractions
- No dedicated rule page yet for unmanaged mobile access (tracked in WP-31).

## Related concepts

- [Social Engineering](social-engineering.md) · [Malware Types and Analysis](malware-types-analysis.md) · [Authentication, MFA and SSO](authentication-mfa-sso.md)
