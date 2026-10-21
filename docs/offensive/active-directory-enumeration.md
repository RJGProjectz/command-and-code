---
title: Enumerate Active Directory for Users, Privileges and Attack Paths
type: workflow
platforms: [Active Directory, Windows]
languages: [PowerShell, Bash]
tasks: [Assessment]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [active-directory, ad, domain, enumeration, bloodhound, sharphound, kerberoasting, asreproast, acl-abuse, lateral-movement, ldap, netexec, crackmapexec, impacket, rubeus, on-prem]
aliases: [enumerate active directory, ad recon, domain enumeration, bloodhound collection, find kerberoastable accounts, asrep roasting, map attack paths, ldap domain enum, netexec smb, crackmapexec enumeration, who is domain admin, ad acl abuse]
difficulty: intermediate
verified: false
---

# Enumerate Active Directory for Users, Privileges and Attack Paths
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Domain enumeration touches identity infrastructure that the whole estate depends on.
> 1. Run **only** against a domain you own or are explicitly authorized to test (signed engagement,
>    in-scope asset, or your own lab).
> 2. Stay inside the agreed scope, rate limit, and time window; keep a log of every query you ran.
> 3. Collection tools (SharpHound, roasting) generate authentication and LDAP traffic that
>    identity-aware defences detect. Start with low-and-slow methods; escalate only as scope allows.
> 4. Treat the output as highly sensitive — it maps the exact path to Domain Admin.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (impacket, NetExec/CrackMapExec,
    BloodHound, Rubeus on Kali/Parrot) but have not been lab-run for this page. Confirm flags against
    each tool's `--help`/docs in your build. Remove this block when `verified: true`.

**Trigger:** you have authenticated (or even unauthenticated) access to a network with an Active
Directory domain and need to understand its users, groups, privileges, and — most importantly — the
**attack paths** that lead from a low-privilege foothold to Domain Admin, so they can be documented and
closed.

**Goal:** move from domain discovery → account and ACL enumeration → attack-path analysis, using the
standard tooling shipped on Kali/Parrot. This is **enumeration and path analysis, not exploitation**;
the defensive counterparts (tiering, LAPS, roasting-resistant accounts) live under
[Hardening → Windows LAPS & admin tiering](../tasks/hardening/windows-laps-admin-tiering.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Domain discovery | `nmap`, `nxc`, `ldapsearch` | Domain controllers, domain name, SMB signing, null-session exposure |
| Account & group enum | `nxc`, `impacket`, PowerView | Users, groups, Domain Admins, password policy, descriptions |
| Kerberos weaknesses | `impacket`, `Rubeus` | Kerberoastable SPNs, AS-REP-roastable accounts |
| Attack-path analysis | `bloodhound-python`, SharpHound, BloodHound | ACL abuse, delegation, shortest path to DA |

## 0. Set the target once

```bash
DOMAIN="corp.example.local"
DC="10.0.0.10"                 # domain controller IP
USER="svc-auth"               # a low-priv domain account (as scope allows)
PASS="REPLACE-with-authorized-cred"
OUT="./ad_${DOMAIN}"
mkdir -p "$OUT"
```

## 1. Find the domain controllers and domain name

```bash
# DCs expose Kerberos (88), LDAP (389/636), SMB (445), and the global catalog (3268)
nmap -Pn -p 88,135,139,389,445,636,3268 -sV -oN "$OUT/nmap-dc.txt" "$DC"

# Pull the domain/forest name and SMB posture without creds (null session, if allowed)
nxc smb "$DC" -u '' -p '' 2>&1 | tee "$OUT/smb-null.txt"
```

`nxc` (NetExec, the maintained fork of CrackMapExec) prints the hostname, domain, OS build, and whether
**SMB signing** is required — an unsigned domain is relay-vulnerable (see
[Network & infrastructure enumeration](network-infrastructure-enumeration.md)).

## 2. Enumerate users, groups and the password policy

With a valid low-privilege credential, read the directory:

```bash
# All domain users (and the password policy / lockout threshold)
nxc smb "$DC" -u "$USER" -p "$PASS" --users | tee "$OUT/users.txt"
nxc smb "$DC" -u "$USER" -p "$PASS" --pass-pol | tee "$OUT/passpol.txt"

# Groups, and who sits in the privileged ones
nxc ldap "$DC" -u "$USER" -p "$PASS" --groups | tee "$OUT/groups.txt"
```

User **description** fields and `userPassword`-style attributes frequently leak passwords — always read
them:

```bash
# impacket: dump all users with descriptions over LDAP
GetADUsers.py -all "$DOMAIN/$USER:$PASS" -dc-ip "$DC" | tee "$OUT/getadusers.txt"
ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" -b "dc=corp,dc=example,dc=local" \
  "(objectClass=user)" sAMAccountName description | tee "$OUT/ldap-desc.txt"
```

## 3. Kerberos weaknesses — roasting

Two offline-crackable conditions are worth identifying because they need **no special privilege**:

```bash
# Kerberoasting: service accounts with an SPN give out crackable TGS tickets
GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request -outputfile "$OUT/kerberoast.hash"

# AS-REP roasting: accounts with "do not require pre-auth" give crackable AS-REP blobs (no creds needed
# if you already have a user list)
GetNPUsers.py "$DOMAIN/" -usersfile "$OUT/userlist.txt" -dc-ip "$DC" -format hashcat \
  -outputfile "$OUT/asrep.hash"
```

These **identify** weak accounts; cracking the hashes offline (`hashcat -m 13100` for TGS, `-m 18200`
for AS-REP) and using them is exploitation — only inside scope. The theory and the fix are in
[Kerberoasting & AS-REP Roasting](../fundamentals/concepts/kerberoasting.md); hunt for it defensively
with [Kerberoasting / AS-REP hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md).

## 4. Collect the graph (BloodHound)

BloodHound turns raw directory data into a graph of **who can reach what**. Collect from Linux with the
Python ingestor, or on-host with SharpHound:

```bash
# Linux collector — pulls sessions, ACLs, group membership, delegation, trusts
bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASS" -ns "$DC" -c All --zip -o "$OUT/bh"
```

```powershell
# On-host collector (run from a domain-joined box, as scope allows)
# SharpHound is part of the BloodHound project; CollectionMethod All gathers ACLs + sessions.
.\SharpHound.exe -c All --zipfilename corp_bh --outputdirectory .
```

Import the resulting `.zip` into the BloodHound GUI, mark your foothold account as **Owned**, and run
the built-in queries — *Shortest Path to Domain Admins*, *Kerberoastable accounts*, *Unconstrained
delegation*, and *Dangerous ACL* queries map the escalation route visually.

## 5. ACL and delegation abuse paths

The highest-value findings are usually **misconfigured rights**, not software bugs:

| Edge BloodHound flags | Why it matters | Note it as |
| :--- | :--- | :--- |
| `GenericAll` / `GenericWrite` on a user | Reset their password or set an SPN → Kerberoast | Over-permissioned ACL |
| `WriteDacl` / `Owns` on a group | Add yourself to a privileged group | ACL escalation |
| `Unconstrained delegation` on a host | Capture TGTs of any user that authenticates to it | Delegation misconfig |
| `AddKeyCredentialLink` (Shadow Credentials) | Authenticate as the target via a forged key | Key-trust abuse |
| DCSync rights (`GetChanges`/`GetChangesAll`) | Replicate password hashes from the DC | Replication rights |

Record each as **what** (the edge), **where** (source → target principal), **evidence** (the
BloodHound path), **severity**, and **fix** (remove the right, tier the account). This is the
reporting phase in [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md).

## 6. Record findings

Keep the raw collector output and BloodHound `.zip` under `"$OUT"` as evidence. Summarize the
escalation story end to end: *foothold account → edge → intermediate principal → Domain Admin*, with
the single highest-leverage fix called out first (usually tiering admin accounts and removing a stray
ACL). Map each fix to the hardening page that implements it.

## Notes

- **NetExec vs CrackMapExec.** `nxc` is the maintained fork; `crackmapexec`/`cme` syntax is nearly
  identical if your build still ships it.
- **Low-and-slow beats loud.** Full SharpHound `-c All` and mass roasting are noisy. Where detection is
  in scope, collect session data separately and throttle, or you will light up the SIEM — which is the
  point of the [Detection](../detection/index.md) tab.
- **Null sessions are a finding.** If step 1 returns users/shares without creds, that misconfiguration
  is itself a reportable issue, independent of anything else you find.
- Install notes: `impacket`, `nxc`/`crackmapexec`, `ldap-utils`, and `bloodhound` (plus
  `bloodhound-python`) all install from the Kali/Parrot repos; `Rubeus`/`SharpHound` are the Windows
  on-host equivalents.

## Related

- [Offensive — Overview](index.md)
- [Windows host enumeration & privilege escalation](windows-host-enumeration-privesc.md)
- [Network & infrastructure enumeration](network-infrastructure-enumeration.md)
- [Kerberoasting & AS-REP Roasting](../fundamentals/concepts/kerberoasting.md) · [Credential Dumping](../fundamentals/concepts/credential-dumping.md) · [Password Attacks](../fundamentals/concepts/password-attacks.md)
- Reference: [LDAP](../fundamentals/identity/ldap.md) · [Identity & Access Management](../fundamentals/concepts/identity-access-management.md)
- Defensive counterparts: [Windows LAPS & admin tiering](../tasks/hardening/windows-laps-admin-tiering.md) · [Kerberoasting / AS-REP hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md)

## External Resources & White Papers

- [BloodHound documentation](https://bloodhound.readthedocs.io/) — collection and attack-path queries
- [Impacket](https://github.com/fortra/impacket) — `GetUserSPNs.py`, `GetNPUsers.py`, `GetADUsers.py`
- [NetExec (nxc)](https://www.netexec.wiki/) — SMB/LDAP enumeration
- [Rubeus](https://github.com/GhostPack/Rubeus) — Windows Kerberos abuse toolkit
- [MITRE ATT&CK — Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007/) and [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/)
