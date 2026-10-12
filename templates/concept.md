---
title: Concept Name                        # the idea itself, e.g. "ARP Spoofing" — not task-phrased
type: concept
platforms: [Windows, Linux]                # from tools/vocabulary.yml — where you meet it
languages: [PowerShell, Bash, KQL]         # languages used in Do it / See it / Detect it
tasks: [Investigation, Threat Hunting]     # which task lanes this concept feeds
category: Network Attacks                  # one free-text category (Concepts index groups on this)
security_domain: Network                   # Identity | Endpoint | Network | Cloud | Application | Operations | Governance | Intelligence
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, tag-one]
aliases: [other name people search for, tool name]
difficulty: basic                          # basic | intermediate | advanced
verified: false                            # true only after checking commands against vendor docs / a lab
---

# Concept Name
> **Created**: 2026-10-11T00:00:00Z
> **Last Modified**: 2026-10-11T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

<!-- =========================================================================
     CONCEPT PAGE RULES (WP-22)
     - Original writing only. Never copy text from another wiki or course.
     - Short: the idea fits on one screen; detail lives on the linked pages.
     - Every page ends in Do it / See it / Detect it. Each of those links to
       pages we already have (tasks/, platforms/, detection/). If we have no
       page yet, say so in one line and add a BACKLOG row — no dead links.
     - "Do it" is the defender's action: inspect, reproduce in a lab you own,
       or check your exposure. No attack walkthroughs against other people.
     ========================================================================= -->

**In one line:** what it is, in plain words.

## What it is

Two to four sentences. Who does it, to what, and what they gain.

## How it works

A short numbered flow or ASCII diagram — the mechanism, not a tutorial.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T0000](https://attack.mitre.org/techniques/T0000/) — Technique name |
| **What it leads to** | the next step an attacker takes with it |
| **Where defenders meet it** | the alert, ticket or symptom that brings you here |

## Do it

Run the related commands from the toolbox (`cc` CLI):

```bash
cc find "concept keyword"
cc view path/to/page.md
```

Safe inspection command on a host you own:

```powershell
# What this shows
```

## See it

What it looks like in data: event IDs, log fields, packet patterns, files left behind.

| Source | What you see |
| :--- | :--- |
| Windows Security log | Event ID and the field that matters |

## Detect it

- Detection: [Rule or query page](../../detection/index.md)
- Hunt: [Hunting workflow](../../tasks/threat-hunting/index.md)
- Respond: [Incident response workflow](../../tasks/incident-response/index.md)
- Harden: [Hardening task](../../tasks/hardening/index.md)

## Related concepts

- [Other concept](other-concept.md)
