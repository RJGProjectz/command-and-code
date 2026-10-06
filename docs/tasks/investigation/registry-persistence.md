---
title: Registry Persistence Investigation
type: workflow
platforms: [Windows, Microsoft Defender, SentinelOne]
languages: [PowerShell, Windows CLI, KQL, S1QL]
tasks: [Investigation, Incident Response, Threat Hunting]
category: Workflow
tags: [workflow, registry, run keys, persistence, autoruns]
aliases: [registry persistence, run key alert, autorun investigation, startup persistence]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Registry Persistence Investigation

**Trigger:** a Run-key / Winlogon / IFEO modification alert, or an unfamiliar autostart entry.

## 1. Enumerate autostart entries on the host

→ [Dump all Run keys and startup folders](../../platforms/windows/registry.md#dump-all-run-keys-and-startup-folders) · [`Get-PersistenceSnapshot.ps1`](../../toolbox/powershell.md#get-persistencesnapshot) · Sysinternals Autoruns for full coverage

## 2. Include every user hive

HKCU only shows the current user. → [Check other users' HKCU](../../platforms/windows/registry.md#check-other-users-hkcu)

## 3. Assess each entry

→ [What to look for](../../platforms/windows/registry.md#what-to-look-for)

## 4. Who wrote it and when?

EDR registry telemetry records the writing process and account.

→ [KQL Run key modifications](../../detection/kql/file-registry-events.md#run-key-modifications) · [KQL Winlogon/IFEO](../../detection/kql/file-registry-events.md#winlogon-and-ifeo-tampering) · [S1QL Run key writes](../../detection/s1ql/hunting.md#run-key-writes)

## 5. Examine the referenced file

→ [Hash and signature](../../platforms/windows/processes.md#check-the-binary-hash-and-signature) · [Mark of the Web](../../platforms/windows/files-directories.md#where-was-this-file-downloaded-from-mark-of-the-web)

## 6. Scope

Search for the same value name, data, or file hash fleet-wide.

## 7. Remediate

Export the key, remove the value, remove the payload, and confirm nothing re-creates it after reboot (a second persistence mechanism often restores the first).

→ [Remove a malicious value](../../platforms/windows/registry.md#remove-a-malicious-value)
