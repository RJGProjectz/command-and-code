---
title: Privilege Escalation Techniques — Awareness, Detection and Hardening
type: workflow
platforms: [Windows, Linux, Active Directory]
tasks: [Assessment, Hardening, Detection Engineering]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [privilege-escalation, privesc, domain-escalation, ACL-abuse, GPO-abuse, token-impersonation, UAC-bypass, PrintNightmare, Zerologon, BloodHound, red-team, stage-4, awareness, blue-team-parity]
aliases: [privesc, domain privilege escalation, local privilege escalation, ACL abuse, GPO abuse, token impersonation, UAC bypass, vertical escalation, horizontal escalation]
difficulty: advanced
verified: false
---

# Privilege Escalation Techniques — Awareness, Detection and Hardening
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

> [!WARNING]
> **Authorized testing only — this is an awareness and defence page, not an attack operations page.**
> These techniques are documented so an authorized assessor understands *how attackers escalate privileges*
> and, above all, so a defender can **detect and harden** against them. Reproduce any technique only inside
> a lab you own under a signed engagement, within agreed scope — see
> [Cyber Law](../fundamentals/concepts/cyber-law.md) and
> [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    This page is conceptual: it links detection and hardening procedures. Confirm every tool and command
    against your own build and vendor docs before relying on them. Remove this block when `verified: true`.

**Trigger:** an authorized red team (or adversary) has established a foothold on a host or low-privilege domain account and now attempts to gain elevated access — Domain Admin, SYSTEM, or access to a privileged service account.

**Goal:** understand the two classes of privilege escalation — local and domain — and the common paths within each, so defenders can instrument, detect, and close them.

---

## 1. Understand the Two Classes

Privilege escalation divides into **local** (gaining elevated rights on a single host) and **domain** (gaining elevated rights within Active Directory, ultimately Domain Admin or equivalent).

| Class | Starting point | End goal | Key tools |
| :--- | :--- | :--- | :--- |
| Local — vertical | Unprivileged shell | SYSTEM / root | WinPEAS, LinPEAS, Mimikatz |
| Local — horizontal | UserA credentials | UserB (same privilege) | Session hijack, credential theft |
| Domain | Domain user | Domain Admin / Enterprise Admin | BloodHound, PowerView, Rubeus, Impacket |

**Vertical escalation** (local) requires exploiting a kernel vulnerability, misconfigured service, unquoted service path, weak registry permission, or token privilege abuse. **Horizontal escalation** occurs when an attacker assumes the identity of another account at the same privilege level — common via session and cookie theft, or credential reuse.

→ [Windows Host Enum & Privesc](windows-host-enumeration-privesc.md)
→ [Linux Host Enum & Privesc](linux-host-enumeration-privesc.md)

---

## 2. Unpatched CVEs (Domain) — Zero2Hero Exploits

Some vulnerabilities convert a domain user directly into Domain Admin without any complex configuration abuse:

| CVE | Name | Attack vector |
| :--- | :--- | :--- |
| CVE-2020-1472 | Zerologon | Unauthenticated reset of the Domain Controller machine account password via the Netlogon protocol |
| CVE-2021-1675 / CVE-2021-34527 | PrintNightmare | Remote code execution as SYSTEM via the Windows Print Spooler service |
| CVE-2021-42278 / CVE-2021-42287 | noPac / sAMAccountName Spoofing | Attacker renames a machine account to match a DC, forges a service ticket as Domain Admin |

Detection signal: anomalous Netlogon traffic, spooler service spawning network connections, machine accounts with unexpected sAMAccountName changes.

**Hardening:** patch aggressively — all three above have vendor patches. Disable Print Spooler on Domain Controllers if print services are not needed (`Set-Service -Name Spooler -StartupType Disabled`). Enable Netlogon `RequireSignOrSeal`.

---

## 3. ACL Abuse

Active Directory objects carry discretionary access control lists (DACLs) that govern who can read, write, or control them. Common misconfigured permissions that enable escalation:

| Right | Target | What an attacker does |
| :--- | :--- | :--- |
| `GenericAll` / `GenericWrite` | User object | Reset the user's password or add an SPN for Kerberoasting |
| `WriteDACL` | Group or OU | Grant themselves `GenericAll` on the container |
| `GenericAll` | Computer object | Perform Resource-Based Constrained Delegation abuse |
| `DCSync` rights (`DS-Replication-Get-Changes-All`) | Domain object | Pull all password hashes from the DC without running code on it |

BloodHound enumerates these paths automatically. An attacker follows the shortest path from their starting node to Domain Admins.

Detection: monitor for `4662` (Object operations — Directory Service access), `4670` (Permissions change on an object), and `4738` (User account changed — unexpected password resets). SACL auditing must be enabled for these events to fire.

**Hardening:** audit ACLs with BloodHound in read-only mode periodically. Remove `GenericAll`, `WriteDACL`, and `GenericWrite` from non-administrative accounts. Enable Protected Users security group for privileged accounts.

→ [Active Directory Enumeration](active-directory-enumeration.md#acl-and-dacl-enumeration)

---

## 4. Group Policy Object (GPO) Abuse

Group Policy Objects control configuration across all computers in a domain or OU. An account with `CreateChild` or `WriteProperty` on a GPO, or `GenericWrite` on an OU that links a GPO, can push malicious configuration to all machines in scope.

Common exploitation: creating a scheduled task or startup script inside the GPO that runs a payload as SYSTEM on every machine in the linked OU.

Detection: `4662` on the `{GUID}` GPO container in AD, and unusual scheduled task creation events (`4698`) across multiple hosts simultaneously.

**Hardening:** restrict GPO creation rights to a named group. Use `Get-GPPermission -All` to audit who can write which GPOs. Enable the `GpoPrivilege` subcategory in Windows Advanced Auditing.

---

## 5. Built-In Group Membership Escalation

Certain built-in AD groups grant indirect paths to Domain Admin even when they are not Domain Admins themselves:

| Group | Why it matters |
| :--- | :--- |
| `Account Operators` | Can add members to most non-protected groups |
| `Backup Operators` | Can read any file on any DC (effectively reads the NTDS.dit) |
| `Print Operators` | Can load drivers and gain SYSTEM on DCs |
| `DNSAdmins` | Can load an arbitrary DLL into the DNS service running on a DC |
| `Server Operators` | Can start/stop services and write to service binaries on DCs |

Detection: monitor for unexpected additions to these groups (`4728` — A member was added to a security-enabled global group). Alert on any change where the source account is not a Tier 0 admin account.

**Hardening:** audit these groups regularly. Follow the tiering model — Tier 0 (domain controllers), Tier 1 (servers), Tier 2 (workstations) — and ensure no Tier 2 account has Tier 0 group membership.

---

## 6. Token Impersonation (Local Escalation)

On Windows, a process can impersonate the identity of another account via token handles. If a low-privileged process holds a token for a high-privileged account (e.g., a SYSTEM service made a network call), an attacker with `SeImpersonatePrivilege` can duplicate that token and open a process in the high-privileged context.

Tools like `PrintSpoofer` and `RoguePotato` exploit local privilege escalation paths using this mechanism. IIS application pools, SQL Server service accounts, and LocalService / NetworkService accounts commonly hold this privilege.

Detection: event `4624` (logon type 3) originating from unusual parent processes; suspicious child processes spawned by `w3wp.exe` or `sqlservr.exe`.

**Hardening:** restrict `SeImpersonatePrivilege` to only accounts that genuinely require it. Enable Windows Credential Guard to protect token handles in isolated memory.

---

## Detect It

- Detection: [Sigma rules for privilege escalation](../../detection/sigma/examples.md)
- Hunt: [Threat Hunting workflow](../../tasks/threat-hunting/index.md)
- Respond: [Incident Response workflow](../../tasks/incident-response/index.md)
- Harden: [Hardening tasks](../../tasks/hardening/index.md)

---

## Related

- [Windows Host Enum & Privesc](windows-host-enumeration-privesc.md)
- [Linux Host Enum & Privesc](linux-host-enumeration-privesc.md)
- [Active Directory Enumeration](active-directory-enumeration.md)
- [Lateral Movement](../../tasks/threat-hunting/lateral-movement.md)
- [Credential Dumping](../../fundamentals/concepts/credential-dumping.md)
- [Kerberoasting](../../fundamentals/concepts/kerberoasting.md)

## External Resources

- [MITRE ATT&CK: Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Microsoft: Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [PrintNightmare Advisory (MSRC)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- [Zerologon Technical Analysis (Secura)](https://www.secura.com/blog/zero-logon)
