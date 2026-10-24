---
title: Enumerate a Linux Host and Identify Privilege-Escalation Paths
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [linux, privilege-escalation, privesc, enumeration, linpeas, suid, sudo, capabilities, cron, kernel, credential-hunting, gtfobins, post-exploitation]
aliases: [linux privilege escalation, linux privesc, enumerate linux host, linpeas, suid binary abuse, sudo misconfig, linux capabilities privesc, writable cron, find credentials on linux, gtfobins, how to escalate on linux]
difficulty: intermediate
verified: false
---

# Enumerate a Linux Host and Identify Privilege-Escalation Paths
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> These commands assume you already have an authorized foothold (a shell) on the host.
> 1. Run **only** on a host you own or are explicitly authorized to test.
> 2. Enumeration is low-risk, but **acting** on a finding (writing to a cron file, abusing a SUID
>    binary) changes the system — stay inside scope and keep a log.
> 3. Leave the host as you found it: note temporary files you create and remove them.
> 4. Treat the output as sensitive — it exposes credentials and escalation routes.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against documented tool behaviour (coreutils, LinPEAS, pspy on Kali/Parrot
    and standard distros) but have not been lab-run for this page. Confirm paths and flags on the
    target build. Remove this block when `verified: true`.

**Trigger:** you have a low-privilege shell on an authorized Linux host and need to find a path to
`root` — or confirm there isn't one — and document the misconfiguration that allows it.

**Goal:** work from host context → automated enumeration → the four classic escalation vectors (SUID,
`sudo`, capabilities, scheduled jobs) → credential hunting. This is **enumeration and identification**;
abusing a finding is only inside a scoped engagement. The fixes are in
[Hardening → Linux CIS access, PAM & SSH](../tasks/hardening/linux-cis-access-pam-ssh.md).

| Stage | Commands / tools | What you learn |
| :--- | :--- | :--- |
| Host context | `id`, `uname`, `cat /etc/os-release` | Who you are, kernel and distro version |
| Automated sweep | `linpeas.sh`, `pspy` | Everything below, ranked, plus live process/cron activity |
| Elevation vectors | `find` SUID, `sudo -l`, `getcap` | Binaries and rights that lead to root |
| Scheduled jobs | `crontab`, `/etc/cron*` | Root-run scripts you can influence |
| Credential hunting | `grep`, history, keys | Reusable passwords and SSH keys |

## 0. Host context (always first)

```bash
id                                   # current user, groups (docker/lxd/disk are escalation groups)
uname -a                             # kernel version — map to known local-root CVEs
cat /etc/os-release                  # distro and release
hostname; ip -brief address         # where you are on the network
sudo -n true 2>/dev/null && echo "passwordless sudo available"
```

The groups in `id` matter: membership of `docker`, `lxd`, `disk`, or `shadow` is often a direct route
to root on its own.

## 1. Automated enumeration (LinPEAS)

Let the standard script do the broad sweep, then read its highlighted findings:

```bash
# Transfer linpeas.sh in-scope, then run it and keep the output
./linpeas.sh -a | tee linpeas.txt

# No script allowed? pspy watches cron/processes run by other users without root
./pspy64 > pspy.txt &
```

LinPEAS colour-codes likely wins (red/yellow = high probability). Treat it as a **lead generator** —
confirm every finding manually below before reporting it.

## 2. SUID / SGID binaries

SUID binaries run as their owner (often root). An unusual one may be abusable per
[GTFOBins](https://gtfobins.github.io/):

```bash
# Find SUID binaries; compare against a known-good baseline for the distro
find / -perm -4000 -type f 2>/dev/null | tee suid.txt
# SGID too
find / -perm -2000 -type f 2>/dev/null
```

A non-standard entry (e.g. `find`, `nmap`, `vim`, a custom binary) is the finding; GTFOBins documents
whether and how each can spawn a shell. Standard SUID binaries (`passwd`, `sudo`, `mount`) are expected.

## 3. `sudo` rights

```bash
# What may this user run as root, and under what conditions?
sudo -l 2>/dev/null | tee sudo-l.txt
```

Read the output carefully: a single `NOPASSWD` entry for an interactive or shell-escaping program
(editors, interpreters, `less`, `tar`, `awk`) is usually a direct escalation — again cross-referenced
on GTFOBins. Note the exact rule as evidence.

## 4. Linux capabilities

Capabilities grant slivers of root power to a binary without the SUID bit:

```bash
# Binaries carrying file capabilities; cap_setuid / cap_dac_override are high-value
getcap -r / 2>/dev/null | tee caps.txt
```

`cap_setuid+ep` on an interpreter (python, perl) lets it set UID 0 — a clean escalation to flag.

## 5. Scheduled jobs you can influence

```bash
# System crontabs and drop-in dirs — look for root jobs running a script YOU can write to
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
# Writable files referenced by root cron jobs are the prize
grep -R -nE '^\*|root' /etc/crontab /etc/cron.d/ 2>/dev/null
```

If a root cron job runs a script that is world-writable (or lives in a writable directory), that
misconfiguration is the escalation. `pspy` from step 1 reveals jobs that are not in these files but
still run as root.

## 6. Credential and key hunting

```bash
# Config files, scripts and backups that embed passwords
grep -RiaE 'password|passwd|secret|api[_-]?key|token' /etc /opt /var/www /home 2>/dev/null | head -50

# Shell history, SSH keys, and cloud credentials
cat ~/.bash_history ~/.*_history 2>/dev/null
find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null
find / -name '.env' -o -path '*/.aws/credentials' 2>/dev/null
```

A reused password or a private key for another host turns a single foothold into lateral movement —
record where it was found and what it unlocks.

## 7. Record findings

Keep `linpeas.txt`, `suid.txt`, `sudo-l.txt`, `caps.txt`, and `pspy.txt` as evidence. For each viable
path, write **what** (the misconfig), **where** (the exact binary/rule/file), **evidence** (the command
output), **severity**, and **fix** — then remove any temporary files you dropped on the host.

## Detect it

The sweep is quiet, but the **exploitation** steps execute binaries and touch credential files — visible
wherever host telemetry is collected, which is what drives the detection content on the
[Detection](../detection/index.md) tab. The signal only exists if the host is logging, so this pairs with
[Linux CIS — auditd Logging](../tasks/hardening/linux-cis-auditd-logging.md) as the telemetry source:

| Offensive technique here | Detect it with |
| :--- | :--- |
| LinPEAS run, SUID abuse, `sudo`/capability misuse spawning shells (§1–§4) | [KQL — Process Event Hunting](../detection/kql/process-events.md) |
| Cron/scheduled-job tampering you can influence (§5) | [KQL — File and Registry Event Hunting](../detection/kql/file-registry-events.md) |
| Credential and SSH-key hunting across the filesystem (§6) | [KQL — Credential Access and Memory Dumping](../detection/kql/credential-access.md) |

A normal user does not read `/etc/shadow`, enumerate every SUID binary, or grep the disk for `password`
— those are the exact actions the defender hunts for once auditd is recording them.

## Notes

- **Enumerate before you act.** The sweep is quiet; abusing a SUID binary or editing a cron script is
  not, and may break the host. Confirm scope first.
- **Groups are escalation, not just identity.** `docker`/`lxd`/`disk` membership (from `id`) is often
  the shortest path — check it before chasing kernel exploits.
- **Kernel exploits last.** A `uname -a` CVE match is tempting but risky (panics, instability); prefer
  a misconfiguration you can demonstrate safely.
- Install notes: `linpeas.sh` and `pspy` are single static binaries you stage in-scope; everything else
  (`find`, `getcap`, `sudo`, `grep`) ships with the base system.

## Related

- [Offensive — Overview](index.md)
- [Network & infrastructure enumeration](network-infrastructure-enumeration.md)
- [Active Directory enumeration](active-directory-enumeration.md)
- Reference: [Linux persistence](../platforms/linux/persistence.md) · [Linux cron](../platforms/linux/cron.md) · [Users & permissions](../platforms/linux/users-permissions.md) · [SSH keys](../fundamentals/identity/ssh-keys.md)
- Defensive counterparts: [Linux CIS access, PAM & SSH](../tasks/hardening/linux-cis-access-pam-ssh.md) · [Linux CIS filesystem & services](../tasks/hardening/linux-cis-filesystem-services.md)

## External Resources & White Papers

- [GTFOBins](https://gtfobins.github.io/) — Unix binaries abusable for shell escape and privesc
- [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng) — privilege-escalation enumeration scripts
- [pspy](https://github.com/DominicBreuker/pspy) — unprivileged process and cron watcher
- [MITRE ATT&CK — Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
