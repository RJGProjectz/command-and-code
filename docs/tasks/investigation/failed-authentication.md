---
title: Failed Authentication Investigation
type: workflow
platforms: [Windows, Windows Server, Linux, Entra ID, Splunk]
languages: [PowerShell, Bash, KQL, SPL]
tasks: [Investigation, Incident Response, Troubleshooting]
category: Workflow
tags: [workflow, failed logons, brute force, password spray, lockout, 4625, 4740]
aliases: [failed windows login, failed logins, account lockout source, brute force investigation, password spray investigation]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
search:
  boost: 3
---

# Failed Authentication Investigation

**Trigger:** spike in failed logons, account lockouts, a brute-force or password-spray alert.

## 1. Classify the pattern

| Pattern | Indicates |
| --- | --- |
| One account, many failures, one source | Brute force — or a stale saved credential |
| Many accounts, few failures each, one source | Password spray |
| Many accounts, many sources | Distributed spray (botnet/proxy network) |
| One account, failures from many internal hosts | Stale credential on mapped drives, services, mobile mail |

## 2. Collect the failures

- Windows endpoint/server → [failed logons summary](../../platforms/windows/event-logs.md#failed-logons-summary)
- Linux → [failed SSH logins](../../platforms/linux/logs.md#failed-ssh-logins)
- Entra ID → [password spray query](../../detection/kql/logon-identity.md#password-spray-against-entra-id)
- Fleet-wide → [SPL 4625](../../detection/spl/windows-events.md#failed-logons-4625) · [KQL failed logons](../../detection/kql/logon-identity.md#failed-logons-on-devices)

## 3. Read the failure reason

Windows `SubStatus`: `0xC000006A` (bad password — the account exists), `0xC0000064` (no such user — enumeration), `0xC0000234` (locked). Entra `ResultType`: 50126, 50053, 53003.

→ [4625 SubStatus codes](../../platforms/windows/event-logs.md#failed-logons-summary) · [Entra result codes](../../detection/kql/logon-identity.md#entra-id-sign-in-logs)

## 4. Find the lockout source

Lockouts (4740) are logged on the **PDC emulator** with `CallerComputerName`.

→ [Find the PDC emulator](../../platforms/windows/windows-server.md#domain-controllers)

## 5. Did any attempt succeed?

The critical question.

→ [KQL success after failures](../../detection/kql/logon-identity.md#successful-sign-in-after-many-failures) · [SPL success after failures](../../detection/spl/windows-events.md#successful-logon-after-failures)

If yes → [Account Compromise](../incident-response/account-compromise.md).

## 6. Characterise the source

Internal host? Investigate that host. External IP? Check ASN, whether it hit other accounts, and whether the targeted service should be internet-exposed at all (RDP, SSH, legacy auth).

## 7. Respond

Block source IPs, enforce lockout/smart lockout, disable legacy authentication, require MFA on the exposed service, fix stale credentials for benign cases.
