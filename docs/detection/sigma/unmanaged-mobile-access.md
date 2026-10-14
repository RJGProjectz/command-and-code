---
title: Detection Rule — Unmanaged Mobile Access to Corporate Apps
type: entry
platforms:
  - Entra ID
  - Intune
  - Microsoft 365
languages:
  - Sigma
  - KQL
tasks:
  - Detection Engineering
  - Compliance
verified: true
last_verified: 2026-10-13
difficulty: basic
tags:
  - mobile
  - byod
  - intune
  - conditional-access
  - signin-logs
---

# Detection Rule — Unmanaged Mobile Access to Corporate Apps

Detects successful sign-ins from iOS or Android devices that are neither managed nor compliant. This is a policy gap
signal more than an attack signal: it shows where Conditional Access does not yet require a compliant device or app
protection policy, and which users are working around it.

!!! warning "Before you deploy"
    Checked (2026-10-13) against Microsoft Learn (`SigninLogs`, sign-in log device details); not run against a live
    tenant. `DeviceDetail` is only populated when the device presents an identity; unregistered devices show an empty
    `deviceId`. If your Conditional Access already blocks unmanaged mobile, this rule should return nothing — a
    result means a policy exclusion or a gap.

- **Concept**: [Mobile Security](../../fundamentals/concepts/mobile-security.md)
- **Harden**: [Conditional Access](../../platforms/microsoft-365/conditional-access.md)

## Sigma rule

```yaml
title: Successful Sign-in from Unmanaged Mobile Device
id: f5cbfdcd-1e19-4443-9fda-cb7eb749ec35
status: experimental
description: Detects successful Entra ID sign-ins from iOS or Android devices that are not managed and not compliant.
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.initial-access
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: 0
    DeviceDetail.operatingSystem|startswith:
      - 'iOS'
      - 'Android'
  managed:
    - DeviceDetail.isManaged: true
    - DeviceDetail.isCompliant: true
  condition: selection and not managed
falsepositives:
  - Users excluded from Conditional Access on purpose (break-glass, pilot groups)
  - Apps protected by Intune app protection (MAM) instead of device enrolment
level: low
```

## KQL (Microsoft Sentinel)

```kql
SigninLogs
| where ResultType == "0"
| extend OS = tostring(DeviceDetail.operatingSystem),
         IsManaged = coalesce(tobool(DeviceDetail.isManaged), false),
         IsCompliant = coalesce(tobool(DeviceDetail.isCompliant), false)
| where OS startswith "iOS" or OS startswith "Android"
| where not(IsManaged) and not(IsCompliant)
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10), IPs = make_set(IPAddress, 10),
            CAResult = make_set(ConditionalAccessStatus)
    by UserPrincipalName, OS
| sort by SignIns desc
```

`ResultType` is a string in `SigninLogs`. The `coalesce` matters: an unregistered phone has no `isManaged` value at
all, and without a default the `not()` test returns null and silently drops exactly the devices this rule is for.
`CAResult` of `notApplied` means no policy covered the sign-in — that is the gap to close.

## Triage

1. Group by `AppDisplayName`: which apps let unmanaged mobile in?
2. Check whether the users are in a Conditional Access exclusion group.
3. Fix by policy (require compliant device or app protection), not by chasing individual users.

## Test it

Atomic Red Team has no test for this (it is a policy gap, not a technique). Sign in to Outlook or Teams with a test
account from a phone that is not enrolled in Intune; the sign-in should appear within the Entra sign-in log delay
(usually a few minutes). If Conditional Access blocks it, `ResultType` is not `0` and the rule correctly stays quiet.

## Sources

- [Microsoft Learn — SigninLogs table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft Learn — Sign-in log activity details (device information)](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-in-log-activity-details)
- [Microsoft Learn — Require compliant device or app protection policy](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance)
