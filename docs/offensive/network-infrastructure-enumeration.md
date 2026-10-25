---
title: Enumerate an Internal Network and its Services
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Network
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [network, enumeration, host-discovery, nmap, smb, ldap, snmp, nfs, responder, relay, internal-pentest, service-enumeration, on-prem]
aliases: [enumerate internal network, network recon, nmap host discovery, smb enumeration, snmp enumeration, nfs exports, ldap anonymous bind, responder llmnr, find live hosts, internal pentest enumeration, service version scan]
difficulty: intermediate
verified: false
---

# Enumerate an Internal Network and its Services
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Network sweeps and poisoning touch every host on the segment.
> 1. Run **only** on a network you own or are explicitly authorized to test.
> 2. Host discovery and service scans are routine but noisy; **poisoning** tools (Responder) answer
>    other machines' traffic and can disrupt a production LAN — use the analyze/passive mode unless
>    active capture is explicitly in scope.
> 3. Stay inside the agreed CIDR, rate, and window; keep a log of what you scanned.
> 4. Treat the output as sensitive — it maps the estate.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against documented tool syntax (nmap, NetExec, enum4linux-ng, Responder on
    Kali/Parrot) but have not been lab-run for this page. Confirm flags against each tool's `--help` on
    your build. Remove this block when `verified: true`.

**Trigger:** you are on an authorized internal network segment and need to know what hosts and services
exist, which are exposed or misconfigured, and where the quick wins are — without yet touching Active
Directory in depth (that is [AD enumeration](active-directory-enumeration.md)).

**Goal:** work from host discovery → port/service enumeration → per-protocol deep dives (SMB, LDAP,
SNMP, NFS) → name-resolution exposure. This is **enumeration and fingerprinting**; the hardening
counterpart is [Per-service egress control](../tasks/hardening/per-service-egress-control.md) and the
network-segmentation guidance under [Microsegmentation](../fundamentals/networking/microsegmentation.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Host discovery | `nmap -sn`, `fping` | Which hosts are live on the segment |
| Port & service scan | `nmap -sV` | Open ports, service/version banners |
| SMB | `nxc smb`, `enum4linux-ng` | Shares, signing, null sessions, OS build |
| LDAP / SNMP / NFS | `ldapsearch`, `snmpwalk`, `showmount` | Directory data, device config, exported filesystems |
| Name resolution | `Responder -A` | LLMNR/NBT-NS/mDNS poisoning exposure (passive) |

## 0. Set the scope once

```bash
CIDR="10.0.0.0/24"             # the authorized segment ONLY
OUT="./net_enum"
mkdir -p "$OUT"
```

## 1. Host discovery

```bash
# Ping sweep — list live hosts without a full port scan
nmap -sn "$CIDR" -oN "$OUT/live-hosts.txt"
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUT/live-hosts.txt" | sort -u > "$OUT/hosts.txt"
```

If ICMP is filtered, add `-PS22,135,445,3389` to probe common TCP ports instead of relying on ping.

## 2. Port and service enumeration

```bash
# Fast first pass across the live hosts: top ports with version detection
nmap -sV -Pn --top-ports 100 -iL "$OUT/hosts.txt" -oA "$OUT/services" 

# Targeted deep scan of an interesting host with the default safe scripts
nmap -sV -sC -Pn -p- --min-rate 1000 10.0.0.50 -oA "$OUT/host-10.0.0.50"
```

`-oA` writes all three formats (`.nmap`, `.gnmap`, `.xml`); the greppable `.gnmap` makes it easy to
pull "all hosts with 445 open" for the next step.

## 3. SMB (445) — shares, signing, sessions

```bash
# Signing status across the subnet — "signing:False" hosts are NTLM-relay targets
nxc smb "$CIDR" --gen-relay-list "$OUT/relay-targets.txt"

# Shares and null-session exposure on one host
nxc smb 10.0.0.50 -u '' -p '' --shares
enum4linux-ng -A 10.0.0.50 | tee "$OUT/enum4linux-10.0.0.50.txt"
```

Readable shares over a null/guest session, and hosts with **SMB signing disabled**, are both reportable
findings — the latter enables the relay path in [AD enumeration](active-directory-enumeration.md).

## 4. LDAP, SNMP and NFS

```bash
# LDAP anonymous bind — does the directory answer without credentials?
ldapsearch -x -H ldap://10.0.0.10 -s base namingContexts | tee "$OUT/ldap-base.txt"

# SNMP with the default "public" community string leaks interfaces, processes, software
snmpwalk -v2c -c public 10.0.0.60 | tee "$OUT/snmp-10.0.0.60.txt"

# NFS exports — world-readable/writable mounts are a classic data-exposure finding
showmount -e 10.0.0.70 | tee "$OUT/nfs-10.0.0.70.txt"
```

A default SNMP community string, an anonymous LDAP bind, or a `no_root_squash`/world-accessible NFS
export each discloses sensitive data with no authentication — note each as its own finding.

## 5. Name-resolution exposure (passive)

Windows networks fall back to LLMNR/NBT-NS/mDNS, which attackers poison to capture hashes. **Confirm
exposure passively first:**

```bash
# Analyze mode: observe LLMNR/NBT-NS/mDNS requests WITHOUT answering them (no poisoning)
responder -I eth0 -A | tee "$OUT/responder-analyze.txt"
```

Seeing broadcast name queries in analyze mode proves the LAN is exposed to poisoning — a high-value
finding on its own. Active capture (dropping `-A`) answers the queries and is **only** for engagements
where that is explicitly in scope; the defensive fix is to disable LLMNR/NBT-NS, detected by
[Sigma → LLMNR / NBT-NS poisoning](../detection/sigma/llmnr-nbtns-poisoning.md).

## 6. Record findings

Keep the nmap `-oA` output and per-protocol logs under `"$OUT"`. Summarize per finding: **what** (e.g.
"SMB signing disabled on 12 hosts"), **where** (host list/CIDR), **evidence** (the tool line),
**severity**, and **fix** (enable signing, change community strings, restrict exports, disable LLMNR).

## Detect it

Host discovery and version scans are expected noise, but at enumeration volume — plus the SMB/LDAP/SNMP
sweeps and any Responder activity — they are visible wherever network and host telemetry is collected,
which is what drives the detection content on the [Detection](../detection/index.md) tab:

| Offensive technique here | Detect it with |
| :--- | :--- |
| Host discovery and port/service scanning (§1–§2) | [SPL — Network and DNS Activity](../detection/spl/network-dns.md) · [KQL — Network Event Hunting](../detection/kql/network-events.md) |
| SMB enumeration, null sessions, relay-target discovery (§3) | [SPL — Lateral Movement over SMB](../detection/spl/lateral-movement-smb.md) |
| LLMNR / NBT-NS / mDNS poisoning exposure (§5) | [Sigma — LLMNR / NBT-NS Poisoning](../detection/sigma/llmnr-nbtns-poisoning.md) |

A single scan is easy to miss; a full subnet sweep plus SMB/LDAP enumeration from one source in a short
window is the pattern the defender hunts for.

## Harden it

Each finding closes with a defensive control:

- **Segment and control egress** (§1–§2) — a flat network is what makes a sweep productive; restrict
  lateral reachability: [Per-service egress control](../tasks/hardening/per-service-egress-control.md).
- **Enforce SMB signing and kill null sessions** (§3) — signing defeats the NTLM-relay path and
  null/guest access leaks shares: [Windows Security Baseline](../tasks/hardening/windows-security-baseline.md).
- **Lock down directory and device services** (§4) — remove anonymous LDAP binds and default SNMP
  community strings and restrict NFS exports: [AD, Kerberos & LDAP Hardening](../tasks/hardening/ad-kerberos-ldap-hardening.md)
  · [Linux CIS — Filesystem & Services](../tasks/hardening/linux-cis-filesystem-services.md).
- **Disable LLMNR / NBT-NS** (§5) — remove the poisoning-prone legacy name resolution:
  [Windows CIS — Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md).

## Notes

- **Passive before active.** Discovery and version scans are expected noise; Responder in active mode
  and aggressive timing (`-T5`) can disrupt fragile hosts — start with `-A`/default timing.
- **Signing list drives the AD phase.** The `--gen-relay-list` output is the input to relay-based
  attacks; even without exploiting it, "signing disabled" is a finding.
- **Default credentials everywhere.** SNMP `public`, anonymous LDAP, and guest SMB are the most common
  real wins on internal networks — check them before anything advanced.
- Install notes: `nmap`, `nxc`/`crackmapexec`, `enum4linux-ng`, `snmp`, `ldap-utils`, `nfs-common`, and
  `responder` all install from the Kali/Parrot repos.

## Related

- [Offensive — Overview](index.md)
- [Active Directory enumeration](active-directory-enumeration.md)
- [Linux host enumeration & privilege escalation](linux-host-enumeration-privesc.md)
- Reference: [Port Scanning](../fundamentals/concepts/port-scanning.md) · [Packet Sniffing](../fundamentals/concepts/packet-sniffing.md) · [Man-in-the-Middle](../fundamentals/concepts/man-in-the-middle.md) · [LDAP](../fundamentals/identity/ldap.md)
- Defensive counterparts: [Per-service egress control](../tasks/hardening/per-service-egress-control.md) · [Sigma — LLMNR / NBT-NS poisoning](../detection/sigma/llmnr-nbtns-poisoning.md)

## External Resources & White Papers

- [Nmap reference guide](https://nmap.org/book/man.html)
- [NetExec (nxc)](https://www.netexec.wiki/) · [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
- [Responder](https://github.com/lgandx/Responder)
- [MITRE ATT&CK — Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007/) and [Network Service Discovery (T1046)](https://attack.mitre.org/techniques/T1046/)
