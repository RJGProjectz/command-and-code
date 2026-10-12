---
title: OSINT and Reconnaissance
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Threat Intelligence, Investigation]
category: Reconnaissance
security_domain: Intelligence
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, osint, recon, attack-surface]
aliases: [OSINT, open-source intelligence, Google Dorking, Reverse Searches, Social Media Account Search, Social Media Scams, reconnaissance]
difficulty: basic
verified: false
---

# OSINT and Reconnaissance
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** collecting what is already public — search engines, DNS, certificates, social media, code repos — to map a target; defenders do it first to shrink their own exposure.

## What it is

Before an attack comes reconnaissance. Most of it never touches your network: search-engine operators ("dorks") that
find exposed files, certificate-transparency logs that list your subdomains, LinkedIn for staff names and email format,
reverse image and username searches that link accounts, leaked credentials in paste sites and breach dumps. Scammers use
the same sources to make social-media and phishing lures convincing.

## How it works

| Source | What it reveals |
| :--- | :--- |
| Search operators (`site:`, `filetype:`, `inurl:`) | exposed documents, login pages, indexes |
| DNS and CT logs (crt.sh) | subdomains, forgotten hosts |
| Social media / job posts | staff, roles, technology stack, email pattern |
| Code repositories | keys and internal hostnames committed by mistake |
| Reverse image / username search | links between accounts, fake profiles |

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance — T1593 search open websites, T1589 gather identity info |
| **What it leads to** | targeted phishing, password spraying with real usernames, attacks on forgotten hosts |
| **Where defenders meet it** | attack-surface reviews, threat-intel collection, scam and impersonation reports |

## Do it

Check your own organisation's exposure (only domains you own or are authorised to assess):

```bash
cc find "threat intelligence"
dig +short TXT example.com              # SPF / verification records reveal SaaS in use
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | python3 -c "import sys,json;print('\n'.join(sorted({r['name_value'] for r in json.load(sys.stdin)})))"
```

```powershell
Resolve-DnsName -Name example.com -Type MX
```

## See it

| Source | What you see |
| :--- | :--- |
| Web logs | crawlers requesting `/.git/`, backups, admin paths |
| Mail gateway | phishing that names real colleagues and projects |
| Brand monitoring | look-alike domains and fake social profiles |

## Detect it

- Intelligence: [Adversary emulation profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md), [IOC lifecycle scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md)
- Reduce exposure: [Email authentication deployment](../../tasks/administration/email-authentication-deployment.md), [DNS](../dns.md)
- Respond: [Phishing email triage](../../tasks/incident-response/phishing-email-triage.md)

## Related concepts

- Social Engineering · [Port Scanning](port-scanning.md)
