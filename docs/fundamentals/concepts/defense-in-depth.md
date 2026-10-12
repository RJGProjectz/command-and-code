---
title: Defense in Depth and Secure Network Design
type: concept
platforms: [Windows, Linux, Azure]
languages: [PowerShell, Bash]
tasks: [Hardening, Assurance]
category: Security Principles
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, defense-in-depth, segmentation, architecture]
aliases: [Defense in Depth, Secure Network Architecture, How to Securely Design Networks, Security Principles, Firewalls and VPNs, layered security, zero trust]
difficulty: basic
verified: false
---

# Defense in Depth and Secure Network Design
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** stack independent controls so that when one fails — and one always does — the next still stops or reveals the attacker.

## What it is

No single product is enough. Defense in depth layers controls across people, process and technology: policy and
training, perimeter firewall, segmented internal networks, hardened hosts, application controls, encryption, monitoring
and tested backups. Zero trust adds a rule on top: never trust a request because of where it comes from; verify identity,
device and context every time.

## How it works

| Layer | Example control | Our page |
| :--- | :--- | :--- |
| Identity | MFA, least privilege, Conditional Access | [Conditional Access](../../platforms/microsoft-365/conditional-access.md) |
| Network edge | default-deny firewall, VPN for remote access | [Firewall default deny](../../tasks/assurance/firewall-default-deny.md), [VPN](../networking/vpn.md) |
| Internal network | segmentation / microsegmentation | [Microsegmentation](../networking/microsegmentation.md) |
| Host | CIS baseline, EDR, application control | [Windows security baseline](../../tasks/hardening/windows-security-baseline.md) |
| Data | encryption at rest and in transit | [BitLocker recovery](../../tasks/administration/bitlocker-recovery.md), [TLS](../networking/tls-ssl.md) |
| Detect & recover | SIEM, backups | [SIEM](siem.md), [Backup and recovery](../../tasks/administration/backup-and-recovery.md) |

Design principles that go with it: [least privilege](cia-triad.md), fail closed, separation of duties, simplicity, and keeping management
interfaces on their own network.

## Why it matters

| | |
| :--- | :--- |
| **Framework** | NIST CSF 2.0 PR (Protect) · NIST SP 800-53 SC-7 boundary protection · CIS Controls 4, 12, 13 |
| **What it leads to** | an attacker who must beat several controls, and more chances to detect them |
| **Where defenders meet it** | architecture reviews, audits, post-incident "what should have stopped this?" |

## Do it

```bash
cc find "baseline" ; cc find "default deny"
```

```powershell
# Is the host firewall on in every profile, with inbound default block?
Get-NetFirewallProfile | Select-Object -Property Name, Enabled, DefaultInboundAction
```

```bash
sudo nft list ruleset | grep -E 'policy (drop|accept)'
```

## See it

| Source | What you see |
| :--- | :--- |
| Firewall logs | which zones talk to which — flat networks show everything talking to everything |
| Compliance scans | baseline drift per layer |

## Detect it

- Assure: [Azure NSG compliance](../../tasks/assurance/azure-nsg-compliance.md), [Firewall default deny](../../tasks/assurance/firewall-default-deny.md)
- Harden: [Firewall port management](../../tasks/administration/firewall-port-management.md), [Azure VNet security](../cloud/azure-vnet-security.md)
- Frameworks: [NIST CSF 2.0](../grc/nist-csf-2.md), [CIS Benchmarks](../grc/cis-benchmarks.md)

## Related concepts

- CIA Triad · Least Privilege · [IDS/IPS](ids-ips.md)
