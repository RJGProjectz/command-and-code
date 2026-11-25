---
title: Ransomware Deployment Techniques
type: concept
platforms: [Windows, Active Directory]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Forensics, Threat Hunting]
category: Malware
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, ransomware, ransomware-deployment, rdp, group-policy, admin-shares, lateral-movement, t1486]
aliases: [ransomware propagation, ransomware execution, ransomware spreading, human-operated ransomware]
difficulty: intermediate
verified: false
# last_verified:
---

# Ransomware Deployment Techniques
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** the final phase of a human-operated ransomware attack is deploying and executing the encryptor across as many hosts as possible — attackers use RDP, Windows administrative shares, and Group Policy to maximise their reach before triggering encryption.

## What it is

Modern ransomware attacks are rarely automated spray-and-pray infections. A ransomware affiliate spends days or weeks inside a network — establishing persistence, escalating privileges, exfiltrating data — before deploying the encryptor. The deployment phase is the last act: the moment when the attacker converts their access into the ransom demand.

Three deployment methods dominate: **remote RDP sessions** that copy and execute the payload host by host, **administrative shares** (C$, ADMIN$) used to push the binary across the network, and **Group Policy Objects (GPOs)** that instruct domain-joined machines to run the encryptor on next policy refresh. Each method requires domain admin or equivalent privileges — which is why privilege escalation precedes this phase every time. [Incident Response Techniques for Ransomware Attacks, pp. 24–26, Ch. 11]

## How it works

```
Initial Access → Post-Exploitation → Privilege Escalation → Data Exfiltration
     → Ransomware Deployment → Encryption → Ransom Note
```

### Method 1 — RDP deployment

The attacker opens an RDP session to a target host (using compromised credentials or Kerberos tickets) and manually copies the ransomware binary, then executes it:

```
# Observed pattern (copied for defensive awareness — do not reproduce)
# mstsc /v:<TARGET_IP> → copy payload to %TEMP%\svchost.exe → execute
```

The Crylock ransomware family was widely documented using this technique. Investigators look for RDP session artefacts: `Security Event 4624` (logon type 10), `TerminalServices-RemoteConnectionManager` events, and new binary files in `%TEMP%` or `%AppData%` directories on victim hosts.

### Method 2 — Administrative shares (ADMIN$, C$)

With domain admin credentials, the attacker uses `net use` or PowerShell remoting to mount the administrative share, copy the payload, then execute it remotely via `PsExec`, `sc.exe`, or `WMI`:

```
# Detection-focused representation
# net use \\<HOST>\ADMIN$ /user:<DOMAIN\Admin> <password>
# copy payload.exe \\<HOST>\ADMIN$\Temp\
# psexec \\<HOST> -u <Admin> C:\Windows\Temp\payload.exe
```

REvil (Sodinokibi) affiliates were observed using this method. Forensic evidence includes `4648` events (logon with explicit credentials), newly created files under `C:\Windows\`, and `4697`/`7045` service creation events from PsExec.

### Method 3 — Group Policy deployment

The attacker creates or modifies a GPO that runs the ransomware binary as a startup script or scheduled task on all domain-joined machines. When policy refreshes (every 90 minutes by default, or on reboot), every machine in scope executes the payload simultaneously.

LockBit 2.0 and 3.0 were extensively documented using GPO-based deployment. Investigators look for newly created GPOs in AD (`Get-GPO -All`), startup script entries in `SYSVOL`, and `4719` events (audit policy changes) around the deployment window.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1486](https://attack.mitre.org/techniques/T1486/) — Data Encrypted for Impact; [T1570](https://attack.mitre.org/techniques/T1570/) — Lateral Tool Transfer; [T1484](https://attack.mitre.org/techniques/T1484/) — Domain Policy Modification |
| **What it leads to** | Mass encryption across dozens or hundreds of hosts within minutes; destruction of shadow copies; exfiltration-then-encrypt double extortion |
| **Where defenders meet it** | Unusual ADMIN$ connections at scale, new GPOs with startup scripts, sudden spike in file rename events (.locked, .encrypted) |

## Do it

Defensive checks you can run on systems you manage:

```powershell
# Check for recently modified GPOs (potential tampered deployment vector)
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-3) } |
    Select-Object DisplayName, ModificationTime, GpoStatus

# List startup scripts in all GPOs via SYSVOL
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter "*.bat","*.cmd","*.ps1","*.exe" -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime | Sort-Object LastWriteTime -Descending
```

> [!CAUTION]
> **SECURITY WARNING**: These queries run against Active Directory and SYSVOL. Use only on networks and domains you are authorised to administer. Any active hunting queries should be conducted within your organisation's authorised change and incident management process.

```powershell
# Hunt for large-scale ADMIN$ lateral connections (requires Security log access)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} |
    Where-Object { $_.Message -match 'ADMIN\$' } |
    Select-Object TimeCreated,
        @{N='User';    E={ $_.Properties[1].Value }},
        @{N='TargetHost'; E={ $_.Properties[8].Value }} |
    Sort-Object TimeCreated -Descending | Select-Object -First 50
```

## See it

| Source | What you look for |
| :--- | :--- |
| Security Event log (4624, type 10) | RDP logons from unexpected sources at unusual hours |
| Security Event log (4648) | Explicit credential use across many hosts in short time window |
| Security Event log (4697, 7045) | New services created by PsExec or similar on multiple hosts |
| Security Event log (4719) | Audit policy or domain policy changes by non-admin accounts |
| SYSVOL | Unexpected .exe, .bat, .ps1 files in Policies\…\Scripts\ |
| File system timeline | Burst of file rename events (new extension appended to every file) |
| VSS / volume shadow copies | Deleted or missing copies (vssadmin delete shadows — T1490) |

## Detect it

- Ransomware general concept: [Ransomware](ransomware.md)
- Lateral movement detection: [Lateral Movement — SMB](../../tasks/threat-hunting/lateral-movement.md)
- Responding to ransomware: [Ransomware Host Isolation](../../tasks/incident-response/ransomware-host-isolation.md)
- Hunt: [Threat Hunting](../../tasks/threat-hunting/index.md)

## Related concepts

- [Ransomware](ransomware.md)
- Credential Theft
- Covering Tracks
- MITRE ATT&CK

## Citations

- Skulkin, O. *Incident Response Techniques for Ransomware Attacks*. Packt, 2022 — pp. 14–26 (attack lifecycle, deployment phase), Ch. 11 pp. 170–185 (RDP, admin shares, GPO deployment investigation).
