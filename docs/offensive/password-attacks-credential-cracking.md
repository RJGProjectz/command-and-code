---
title: Assess Credential Strength — Authorized Password Spraying and Offline Hash Cracking
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-23
last_updated: 2026-10-23
tags: [password-attacks, password-spraying, password-guessing, credential-cracking, hash-cracking, offline-cracking, hashcat, john-the-ripper, john, hashid, wordlists, rules, mangling, kerbrute, netexec, crackmapexec, hydra, account-lockout, password-policy, ntlm, nt-hash, credential-dumping, kerberoasting, parrot-os, kali]
aliases: [password attacks, password spraying, password guessing, credential cracking, crack hashes, offline cracking, hashcat workflow, john the ripper, hash identification, identify hash type, wordlist rules, kerbrute spray, netexec spray, crackmapexec, hydra, low and slow spray, account lockout aware, assess password strength, credential strength assessment]
difficulty: intermediate
verified: false
---

# Assess Credential Strength — Authorized Password Spraying and Offline Hash Cracking
> **Created**: 2026-10-23T00:00:00Z
> **Last Modified**: 2026-10-23T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Credential attacks lock accounts out, create real logon events, and touch personal data — treat them
> with the same discipline as any production change.
> 1. Spray or guess **only** against accounts and services named in a signed engagement or in your own
>    lab. A single careless spray can lock out a whole directory; confirm the target's **lockout policy**
>    before the first attempt and stay under its threshold with a wide delay (§2).
> 2. **Crack offline, in the lab.** Hashes you are authorized to export are cracked on an **isolated**
>    workstation (§3) — never upload a client's hashes to an online cracking service, and never exfiltrate
>    them from the target estate. Offline cracking touches no target system; it is bounded only by the
>    password's strength and your wordlist.
> 3. **Obtaining hashes is out of scope here.** This page assesses the *strength* of credentials you are
>    authorized to test; how an attacker **dumps** hashes from memory or a directory is documented for
>    **awareness and detection only** (§4), never as tooling. Harvested usernames and any cracked
>    passwords are sensitive — store them with the evidence and handle them under
>    [Cyber Law](../fundamentals/concepts/cyber-law.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (hashcat, John the Ripper, kerbrute,
    NetExec; Parrot OS / Kali packages) but have not been lab-run for this page. Hash modes, flags and
    lockout behaviour vary by version and by target — confirm each flag against the tool's
    `--help`/man page and confirm the lockout policy against the target before you spray. Remove this
    block when `verified: true`.

**Trigger:** an authorized engagement has reached **Stage 2 (Initial Access)** and you have either a list
of valid usernames (from [Active Directory Enumeration](active-directory-enumeration.md),
[OSINT & Active Reconnaissance](osint-active-recon.md), or a service that leaks them) or a set of
password hashes you are authorized to export from a lab host, and you need to answer one question: **are
the organization's credentials strong enough to resist guessing?**

**Goal:** produce an evidenced verdict on credential strength — which accounts fall to a short, policy-aware
**password spray**, and which exported hashes fall to **offline cracking** — without locking out
production accounts and without executing the credential-dumping step that would precede cracking in a
real intrusion. This page is part of Stage 2 (Initial Access) of the
[red-team lifecycle](index.md). Its username inputs come from
[Active Directory Enumeration](active-directory-enumeration.md) and
[OSINT & Active Reconnaissance](osint-active-recon.md); a cracked credential hands back to the host and
directory enumeration workflows. For the theory and defenses, see
[Password Attacks and Defences](../fundamentals/concepts/password-attacks.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Scope & inputs (§0–§1) | engagement docs, enum output | Which accounts/services/hashes are in scope; the lockout policy |
| Online spray (authorized) (§2) | `kerbrute`, `netexec`, `hydra` | Which accounts a weak password policy lets in — one password, many users, slow |
| Hash identification (§3a) | `hashid`, `hashcat --identify` | The hash **mode**, so cracking targets the right algorithm |
| Offline cracking (authorized lab) (§3b) | `hashcat`, `john`, wordlists + rules | Which exported hashes fall to guessing, and how fast |
| *Credential dumping (know-it only)* (§4) | *theory — no tooling* | *How attackers obtain hashes — documented for detect/harden, not run here* |

## 0. Set the scope once

```bash
# In-scope ONLY — fill from the engagement. A spray hits a real directory; a lockout is a real outage.
TARGET_DC="dc01.corp.example"            # the authorized auth endpoint (KDC / LDAP / SMB / web SSO)
DOMAIN="corp.example"
USERS="./users_in_scope.txt"             # authorized usernames (from AD/OSINT enum), one per line
OUT="./cred_assessment_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
cp "$USERS" "$OUT/users.txt"

# RECORD the lockout policy BEFORE any spray. On Windows/AD, read it from an authorized session:
#   net accounts /domain        (Lockout threshold / Lockout observation window)
# Stay strictly under the threshold, per observation window, across ALL tools you run.
LOCKOUT_THRESHOLD=5                       # REPLACE with the real value
SAFE_ATTEMPTS=$((LOCKOUT_THRESHOLD - 2))  # leave headroom; never reach the threshold
```

## 1. Choose spraying, not brute force

Two very different techniques share the name "password attack":

- **Brute force / guessing** throws many passwords at **one** account — it trips lockout almost
  immediately and is only appropriate against a lab account or a service with no lockout that the scope
  explicitly allows.
- **Password spraying** tries **one** common password across **many** accounts, then waits out the
  lockout observation window before the next password. It stays under per-account lockout thresholds and
  is the technique for a live, authorized directory.

Against a production directory, **spray**. Build a small, policy-aware candidate list — seasonal and
company-themed passwords that satisfy the complexity rules but not the spirit of them:

```bash
# A SHORT, hand-built list — a handful of guesses, not a wordlist. One password per spray round.
cat > "$OUT/spray_candidates.txt" <<'EOF'
Autumn2026!
Winter2026!
Company@123
Welcome1!
EOF
```

## 2. Online password spray *(scope must allow auth attempts; stay under lockout)*

Spray one password at a time across the in-scope users, then **wait a full lockout observation window**
before the next. Most directory protocols can be sprayed; pick the one the engagement authorizes.

`kerbrute` sprays AD over **Kerberos pre-auth** — it is quiet (no Windows logon-failure 4625 on older
setups, though it does raise Kerberos 4768/4771) and also validates which usernames exist:

```bash
# First: which of the enumerated usernames are real (userenum raises no logon-failure events)
kerbrute userenum -d "$DOMAIN" --dc "$TARGET_DC" "$OUT/users.txt" -o "$OUT/valid_users.txt"

# Spray ONE password across valid users. Repeat per password, waiting out the observation window between.
kerbrute passwordspray -d "$DOMAIN" --dc "$TARGET_DC" "$OUT/valid_users.txt" 'Autumn2026!' \
  -o "$OUT/spray_kerbrute.txt"
```

`netexec` (the maintained successor to CrackMapExec) sprays SMB/LDAP/WinRM and honours a continue-on-success
flag so you can see every hit. Its `--continue-on-success` plus a single password keeps it a spray:

```bash
# SMB spray, one password, all users — read the lockout cushion you set in §0
netexec smb "$TARGET_DC" -u "$OUT/valid_users.txt" -p 'Autumn2026!' --continue-on-success \
  | tee "$OUT/spray_netexec_smb.txt"
```

For non-AD services (SSH, a web login form, an API, FTP) `hydra` sprays a single password across a user
list — again one password per round, with a delay:

```bash
# Example: SSH. -p = one password; -t low to stay gentle; add -W <sec> between attempts if supported.
hydra -L "$OUT/valid_users.txt" -p 'Welcome1!' -t 4 ssh://"$TARGET_DC" | tee "$OUT/spray_hydra_ssh.txt"
```

Record every **success** as a finding (account + the weak password class, not plastered across the
report) and every **lockout** immediately — if you see one, **stop**, because your threshold accounting
is wrong. A single valid credential is the Stage 2 result; hand it to
[Active Directory Enumeration](active-directory-enumeration.md) or the host-enumeration workflows for
authenticated context.

## 3. Offline hash cracking *(authorized lab, isolated workstation)*

When the engagement authorizes exporting hashes from a lab host (for example NTLM hashes from a lab SAM,
a Kerberoast ticket hash, or a Linux `/etc/shadow` entry), cracking is done **offline** on an isolated
machine. It touches no target system and proves whether the underlying passwords are strong.

### 3a. Identify the hash first

Cracking the wrong mode wastes hours. Identify the algorithm before you start:

```bash
# hashid names likely types; hashcat can confirm its own mode number
hashid '<a-single-example-hash>'
hashcat --identify "$OUT/hashes.txt"        # suggests the -m mode for the file
```

Common modes you will meet: NTLM (`-m 1000`), NetNTLMv2 (`-m 5600`), Kerberos 5 TGS-REP /
Kerberoast (`-m 13100`), `sha512crypt` `$6$` from Linux shadow (`-m 1800`), and bcrypt `$2*$`
(`-m 3200`). See the [Kerberoasting](../fundamentals/concepts/kerberoasting.md) concept for where
roastable `-m 13100` hashes come from.

### 3b. Crack with a wordlist, then rules

Start with a straight wordlist, then multiply its reach with a **rule set** (mangling: capitalisation,
leet, appended digits/years) before ever resorting to mask/brute runs:

```bash
WORDLIST=/usr/share/wordlists/rockyou.txt    # decompress rockyou.txt.gz first on Kali/Parrot

# Straight wordlist run (example: NTLM). hashcat picks up the GPU automatically.
hashcat -m 1000 -a 0 "$OUT/hashes.txt" "$WORDLIST" -o "$OUT/cracked.txt"

# Multiply reach with a rule set — the single highest-value step after a plain wordlist
hashcat -m 1000 -a 0 "$OUT/hashes.txt" "$WORDLIST" -r /usr/share/hashcat/rules/best64.rule \
  -o "$OUT/cracked.txt"

# John the Ripper is the portable alternative (auto-detects many formats)
john --format=nt --wordlist="$WORDLIST" --rules "$OUT/hashes.txt"
john --show --format=nt "$OUT/hashes.txt"    # review what cracked
```

The **result that matters for the report** is not the plaintext itself but the *statistic*: what fraction
of hashes fell, and how quickly. "38% of domain hashes cracked in under an hour against a public
wordlist" is the finding that drives a password-policy change. Store the raw cracked output as evidence;
quote categories (weak, reused, policy-compliant-but-guessable) in the report, not a dump of live
passwords.

## 4. Credential dumping — *know it, detect it, harden it (not run here)*

The step that produces the hashes §3 cracks — **credential dumping** — is where an intrusion turns
weaponized: reading them from LSASS memory, the SAM/SECURITY hives, `ntds.dit`, or `/etc/shadow` after a
foothold. This project is enumeration/assessment-only, so **no dumping tooling or procedure is published
here.** You need to understand it only to (a) know where §3's hashes legitimately come from in a lab, and
(b) detect and harden against it on your own estate:

- **Know it:** [Credential Dumping](../fundamentals/concepts/credential-dumping.md) explains LSASS /
  SAM / NTDS / shadow extraction and why protections like Credential Guard and LSASS PPL exist.
- **It feeds this page:** a dumped or roasted hash is the input to §3 — which is exactly why offline
  cracking resistance (long, random, unique passwords) is the control that matters even after a dump.

The takeaway for the assessment: a successful spray (§2) or a high offline-crack rate (§3) is a reportable
finding on its own — you do **not** need to dump production credentials to prove the organization's
passwords are too weak.

## Detect it

Online guessing is **loud**; offline cracking is **invisible** (it touches nothing). The visible steps
drive detection content on the [Detection](../detection/index.md) tab — pair each technique with what
catches it:

| Offensive technique here | Detect it with |
| :--- | :--- |
| Password spray / guessing — many accounts, one password, repeated failures (§2) | [SPL — Brute Force Success Correlation](../detection/spl/brute-force.md) · [KQL — Logon and Identity Hunting](../detection/kql/logon-identity.md) |
| Kerberos pre-auth spray / user enumeration (§2, `kerbrute`) | [KQL — Logon and Identity Hunting](../detection/kql/logon-identity.md) |
| A spray hitting a planted decoy account | [Sigma — Honeytoken and Honey Account Use](../detection/sigma/honeytoken-access.md) |
| Credential dumping that *produces* crackable hashes (§4) | [KQL — Credential Access and Memory Dumping](../detection/kql/credential-access.md) |

Offline cracking (§3) leaves no target-side trace — which is why defenders cannot "alarm" on it and must
instead make the hashes uncrackable (length + uniqueness) and detect the **dump** that precedes it.

## Harden it

Every finding on this page maps to a control:

- **Account lockout + strong password policy** defeats spraying — [Windows CIS — User Rights Assignment &
  Account Policies](../tasks/hardening/windows-cis-user-rights-assignment.md) and
  [Linux CIS — Access Control, PAM & SSH Hardening](../tasks/hardening/linux-cis-access-pam-ssh.md)
  (`pam_pwquality`, `pam_faillock`).
- **Long, random, unique passwords (and MFA)** defeat offline cracking — a 16+ character random secret is
  not in any wordlist. [Deploy Windows LAPS and Admin Tiering](../tasks/hardening/windows-laps-admin-tiering.md)
  randomises local admin passwords so a cracked hash does not travel.
- **Protocol hardening** shrinks what can be roasted or sprayed —
  [AD Kerberos & LDAP Protocol Hardening](../tasks/hardening/ad-kerberos-ldap-hardening.md).

## Notes

- **Spray, don't brute force, against a live directory.** One password across many accounts, then wait
  the full observation window. Know the lockout threshold **before** the first attempt (§0).
- **A lockout is an incident you caused.** If one account locks, stop immediately — your accounting is
  wrong. Err well under the threshold.
- **Crack offline and in the lab.** Never upload a client's hashes to an online service; never exfiltrate
  them. Cracking proves password *strength* and touches no target.
- **Report the statistic, not the plaintext.** "N% cracked in T against a public wordlist" drives policy;
  a dump of live passwords is a liability.
- **Dumping is out of scope.** §3's hashes come from an authorized lab export; the production-dump step is
  awareness/detection only (§4).
- Install notes: `hashcat`, `john` (John the Ripper), `hydra`, `hashid` and the `wordlists` package
  (rockyou) ship on or `apt install` onto Parrot/Kali; `kerbrute` and `netexec` are separate installs.

## Related

- [Offensive — Overview](index.md) — this is part of Stage 2 (Initial Access)
- [Active Directory Enumeration](active-directory-enumeration.md) · [OSINT & Active Reconnaissance](osint-active-recon.md) — where the in-scope usernames come from
- [Enumerate a Windows Host and Identify Privilege-Escalation Paths](windows-host-enumeration-privesc.md) · [Enumerate a Linux Host and Identify Privilege-Escalation Paths](linux-host-enumeration-privesc.md) — where a valid credential goes next
- Reference: [Password Attacks and Defences](../fundamentals/concepts/password-attacks.md) · [Credential Dumping](../fundamentals/concepts/credential-dumping.md) · [Kerberoasting](../fundamentals/concepts/kerberoasting.md) · [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md)
- Defensive counterparts: [Windows CIS — User Rights Assignment & Account Policies](../tasks/hardening/windows-cis-user-rights-assignment.md) · [Linux CIS — Access Control, PAM & SSH Hardening](../tasks/hardening/linux-cis-access-pam-ssh.md) · [AD Kerberos & LDAP Protocol Hardening](../tasks/hardening/ad-kerberos-ldap-hardening.md)

## External Resources & White Papers

- [OWASP Testing Guide — Testing for Weak Password Policy](https://owasp.org/www-project-web-security-testing-guide/) — the methodology this page follows
- [hashcat](https://hashcat.net/hashcat/) · [hashcat example hashes (mode reference)](https://hashcat.net/wiki/doku.php?id=example_hashes) · [John the Ripper](https://www.openwall.com/john/)
- [kerbrute](https://github.com/ropnop/kerbrute) · [NetExec](https://github.com/Pennyw0rth/NetExec)
- [NIST SP 800-63B — Digital Identity Guidelines (password guidance)](https://pages.nist.gov/800-63-3/sp800-63b.html) — the modern length-over-complexity policy that beats cracking
