---
title: Detection Rule — Honeytoken and Honey Account Use
type: entry
platforms:
  - Active Directory
  - Windows Server
  - Microsoft Defender
languages:
  - Sigma
  - KQL
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-13
difficulty: intermediate
tags:
  - honeytoken
  - deception
  - honey-account
  - kerberoasting
  - 4769
  - t1558.003
---

# Detection Rule — Honeytoken and Honey Account Use

A honey account is a real-looking AD account nobody uses; a honey SPN is a fake service principal on it. Any logon,
Kerberos ticket or directory read that touches them is close to a guaranteed true positive, so the rule needs no
threshold.

!!! warning "Before you deploy"
    Event fields were checked (2026-10-13) against Microsoft Learn (events 4662, 4768, 4769, 4771, 4776) and Defender
    for Identity; not run against a live domain. Replace `svc-backup-legacy` and the GUID with your own honey objects.
    Event 4662 needs a SACL on the honey object **and** the *Audit Directory Service Access* subcategory on domain
    controllers; 4768/4769 come from domain controllers only. Exclude your own deception health checks by source host.

- **ATT&CK**: [T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/), [T1087.002 — Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/)
- **Concept**: [Surveillance & Deception](../../fundamentals/concepts/surveillance-deception.md)

## Set-up (once)

1. Create a disabled-looking but **enabled** user with a long random password, plausible name and description, never used.
2. Add a fake SPN (`setspn -S MSSQLSvc/sql-legacy01.corp.local:1433 svc-backup-legacy`) to attract Kerberoasting.
3. Add an audit SACL (Everyone, Read all properties) on the account so directory reads raise 4662.
4. In Defender for Identity, tag the account as **Honeytoken** to get built-in alerts as well.

## Sigma rule

```yaml
title: Honey Account or Honey SPN Activity
id: 15cb8bb5-be04-4d26-b4aa-963ca3834e03
status: experimental
description: Detects any logon attempt, Kerberos ticket request or audited directory read involving a honey account.
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.credential-access
  - attack.discovery
  - attack.t1558.003
  - attack.t1087.002
logsource:
  product: windows
  service: security
detection:
  auth:
    EventID:
      - 4624
      - 4625
      - 4648
      - 4768
      - 4771
      - 4776
    TargetUserName: 'svc-backup-legacy'
  kerberoast:
    EventID: 4769
    ServiceName: 'svc-backup-legacy'
  directory_read:
    EventID: 4662
    ObjectName|contains: '00000000-0000-0000-0000-000000000000'  # honey object GUID
  condition: auth or kerberoast or directory_read
falsepositives:
  - Deception platform health checks
  - Broad AD inventory tools reading every object (directory_read only)
level: critical
```

## KQL (Microsoft Sentinel)

```kql
let honey = dynamic(["svc-backup-legacy"]);
SecurityEvent
| where EventID in (4624, 4625, 4648, 4768, 4769, 4771, 4776, 4662)
| where TargetUserName in~ (honey) or ServiceName in~ (honey)
    or (EventID == 4662 and ObjectName has "00000000-0000-0000-0000-000000000000")
| project TimeGenerated, Computer, EventID, Activity, TargetUserName, ServiceName,
          IpAddress, WorkstationName, SubjectUserName
```

With Defender for Identity the tagged account also appears in `IdentityLogonEvents` and raises "Honeytoken activity" alerts:

```kql
IdentityLogonEvents
| where AccountName =~ "svc-backup-legacy"
| project Timestamp, ActionType, Protocol, DeviceName, IPAddress, DestinationDeviceName
```

## SPL

```spl
index=wineventlog source="XmlWinEventLog:Security"
    ((EventCode IN (4624,4625,4648,4768,4771,4776) TargetUserName="svc-backup-legacy")
    OR (EventCode=4769 ServiceName="svc-backup-legacy")
    OR (EventCode=4662 ObjectName="*00000000-0000-0000-0000-000000000000*"))
| table _time, host, EventCode, TargetUserName, ServiceName, TicketEncryptionType, IpAddress, WorkstationName, SubjectUserName
```

## Triage

1. 4769 for the honey SPN with ticket encryption `0x17` (RC4) is Kerberoasting — the requesting account (`TargetUserName`) is compromised or misused. In 4769, `ServiceName` is the account the ticket is for.
2. 4625/4771 against the honey account usually means password spraying; widen to all failures from that source IP.
3. Follow [Account compromise](../../tasks/incident-response/account-compromise.md) for the account and host that made the request.

## Test it

- Atomic Red Team [T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md)
  *Request for service tickets* and *Rubeus kerberoast* request tickets for every SPN, including the honey SPN: one 4769
  per run with `ServiceName` = the honey account.
- Atomic Red Team [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md)
  *Enumerate all accounts via PowerShell (Domain)* reads every user object: 4662 on the honey object if the SACL is in place.
- One failed `runas /user:<DOMAIN>\svc-backup-legacy cmd` with a wrong password gives 4625 and 4771.

## Sources

- [Microsoft Learn — Event 4769](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft Learn — Event 4662](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
- [Microsoft Learn — Defender for Identity entity tags (honeytoken)](https://learn.microsoft.com/defender-for-identity/entity-tags)
- [Microsoft Learn — IdentityLogonEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identitylogonevents-table)
