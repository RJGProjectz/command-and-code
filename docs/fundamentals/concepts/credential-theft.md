---
title: Credential Theft
type: concept
platforms: [Windows, Active Directory]
languages: [PowerShell, KQL]
tasks: [Incident Response, Threat Hunting, Hardening]
category: Identity Attacks
security_domain: Identity
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, credential-theft, pass-the-hash, pass-the-ticket, ntlm, kerberos, lateral-movement]
aliases: [Pass the Hash, Pass the Ticket, NTLM relay, credential reuse, authentication protocol abuse]
difficulty: intermediate
verified: false
---

# Credential Theft
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** credential theft is the capture or reuse of authentication tokens — hashes, tickets, or session keys — so an attacker can authenticate as someone else without knowing their password.

## What it is

Windows authentication keeps two long-term secrets available at runtime so users do not type their password on every resource access: NTLM stores a hash of the password, and Kerberos stores a Ticket-Granting Ticket (TGT) in the Local Security Authority (LSA). Both are encrypted, but the encryption only matters if the attacker cannot read memory directly. With local administrator or SYSTEM rights, they can.

Credential theft is the class of attacks that capture those runtime secrets and replay them. Unlike credential dumping — which focuses on pulling hashes out of NTDS.dit or LSASS on a single machine — credential theft encompasses the full lifecycle: the capture technique, the protocol used to replay the secret, and the lateral movement that follows.

Three protocols underpin most Windows credential theft:

- **LAN Manager (LM)** — obsolete 1980s protocol. Passwords split into two 7-character halves, each DES-encrypted. Trivially brute-forced in minutes. Disabled by default since Windows Vista, but still seen in legacy OT/industrial environments.
- **NTLM** — the modern replacement. Stores an MD4 hash of the user's password. Used in a challenge-response handshake: the server sends a random nonce, the client signs it with the hash. Critically, the hash is the secret — knowing it is equivalent to knowing the password for authentication purposes.
- **Kerberos** — the preferred Windows domain protocol since Windows 2000. A three-phase exchange issues time-limited tickets: the TGT grants access to the ticket-granting service, which issues service tickets (TGS). Tickets are opaque blobs encrypted with keys the holder cannot read — but they can still be captured from memory and replayed.

## How it works

```text
Target machine (compromised)
   └── attacker has local admin / SYSTEM
         ├── Pass-the-Hash (NTLM)
         │     Read NTLM hash from LSA/SAM/NTDS.dit
         │     Inject hash into a new logon session
         │     Authenticate to remote resources without cracking
         │
         ├── Pass-the-Ticket (Kerberos)
         │     Export TGT or TGS from LSASS memory
         │     Import ticket into a different logon session
         │     Authenticate without re-contacting the KDC
         │
         └── NTLM Relay (network-side)
               Capture NTLM challenge from victim host
               Forward to a target server
               Authenticate to the target as the victim
```

**Pass-the-Hash (PtH):** NTLM's challenge-response means the server never sees the plaintext password — only the hash-signed nonce. An attacker who extracts an NTLM hash from LSASS memory can load it directly into an authentication context (using tools such as Mimikatz's `sekurlsa::pth`) and connect to any service that accepts that account. Domain admin hashes obtained from a single domain controller dump translate immediately to lateral movement across the entire domain.

**Pass-the-Ticket (PtT):** Kerberos tickets are time-limited (TGTs: 10 hours, renewable for 7 days). If an attacker extracts a TGT from memory with `sekurlsa::tickets /export` and imports it into a new session, they inherit the original user's access until the ticket expires. The Key Distribution Center is not contacted during the replay — validation happens at the service endpoint.

**DCSync:** Rather than touching LSASS on a domain controller directly, an attacker with `DS-Replication-Get-Changes-All` rights can impersonate a replication partner and request password hashes for any account in the domain. The built-in tool call is:

```text
lsadump::dcsync /all /csv
```

This is a replication protocol feature, not a vulnerability — which is why it is difficult to block and easy to miss.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) — Pass the Hash · [T1550.003](https://attack.mitre.org/techniques/T1550/003/) — Pass the Ticket · [T1003.006](https://attack.mitre.org/techniques/T1003/006/) — DCSync |
| **What it leads to** | domain-wide lateral movement; one compromised admin hash is a skeleton key for the environment |
| **Where defenders meet it** | logon type 9 (`seclogon`) events, Kerberos TGT requests from unusual hosts, DCSync replication traffic from non-DC sources |

## Do it

Check which authentication protocols are permitted and whether NTLM is constrained:

```powershell
# NTLM audit policy (0=off, 1=all, 2=domain accounts only)
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name AuditReceivingNTLMTraffic -EA SilentlyContinue).AuditReceivingNTLMTraffic

# Minimum session security settings (require NTLMv2 + 128-bit)
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinClientSec).NtlmMinClientSec
# 537395200 = NTLMv2 + 128-bit (correct value)

# Is Credential Guard running? (blocks NTLM hash extraction from LSASS)
(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning
# 1 = Credential Guard active
```

> [!CAUTION]
> **SECURITY WARNING:** Run on hosts you own or are authorised to assess. These read-only registry queries do not modify the system; use `-WhatIf` with any changes.

## See it

| Source | What you see |
| :--- | :--- |
| Security log — Event 4624 (logon) | Logon Type 9 (`NewCredentials`) from `sekurlsa::pth`; NTLM logons to hosts the account never reached before |
| Security log — Event 4776 (NTLM auth) | NTLM auth attempts from unexpected workstations or at unusual hours |
| Security log — Event 4662 (object access) | DCSync: access to the domain NC object with `1131f6aa-*` (Get-Changes) or `1131f6ad-*` (Get-Changes-All) rights from a non-DC source |
| Directory Services log — Event 4929 | Source NC replica deletion — rare; investigate immediately |
| Sysmon Event 10 (ProcessAccess) | `TargetImage: lsass.exe` with broad `GrantedAccess` from unexpected processes |

## Detect it

- Detection: [KQL credential access and memory dumping](../../detection/kql/credential-access.md)
- Hunt: [Lateral movement hunting](../../tasks/threat-hunting/lateral-movement.md)
- Respond: [Account compromise investigation](../../tasks/incident-response/account-compromise.md)
- Harden: [Credential Guard and ASR](../../tasks/hardening/windows-cis-attack-surface-reduction.md) · [User rights assignment](../../tasks/hardening/windows-cis-user-rights-assignment.md)

## Related concepts

- [Credential Dumping](credential-dumping.md)
- [Kerberoasting](kerberoasting.md)
- [Password Attacks](password-attacks.md)
- [Lateral Movement](../../tasks/threat-hunting/lateral-movement.md)
