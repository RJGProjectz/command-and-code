---
title: Investigate the Situation             # e.g. "Suspicious Service Investigation"
type: workflow
platforms: [Windows]
languages: [PowerShell, KQL]
tasks: [Incident Response, Investigation]
category: Workflow
tags: [workflow, topic]
aliases: [phrases an analyst would search with]
difficulty: intermediate
verified: false
# last_verified: 2026-10-05
---

# Investigate the Situation

**Trigger:** the alert or observation that starts this workflow.

**Goal:** the decision this workflow lets you make.

<!-- Rules: every step links to an entry instead of repeating its commands.
     Inline a command only when it is specific to this workflow.
     Keep steps short — this is a field reference, not an essay. -->

## 1. First step

What to establish and why.

→ [Entry that shows how](../../platforms/windows/page.md#heading)

## 2. Second step

→ [Entry](../../platforms/windows/page.md#heading) · [Query](../../detection/kql/page.md#heading)

## 3. Scope

→ fleet-wide queries

## 4. Contain and remediate

| Finding | Action |
| --- | --- |
| Confirmed malicious | … |
| Benign | Document and tune |

## Related

- [Other workflow](other-workflow.md)
