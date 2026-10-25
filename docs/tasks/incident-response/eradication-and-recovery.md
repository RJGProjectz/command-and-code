---
title: Eradication and Recovery
type: workflow
platforms: [Windows, Windows Server, Linux, Entra ID, Microsoft 365]
languages: [PowerShell, Bash]
tasks: [Incident Response, Administration, Hardening]
category: Workflow
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-24
last_updated: 2026-10-24
tags: [incident-response, eradication, recovery, persistence-removal, reimage, restore-from-backup, re-hardening, entry-vector, nist-800-61, lifecycle]
aliases: [eradication, recovery, remove persistence, close the entry vector, rebuild vs restore, reimage or restore, return to production after incident, re-harden after compromise, how to recover from a breach, post-containment cleanup]
difficulty: advanced
verified: false
---

# Eradication and Recovery
> **Created**: 2026-10-24T00:00:00Z
> **Last Modified**: 2026-10-24T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This workflow removes attacker footholds and returns systems to production. Before running any action:
> 1. Confirm the incident is **contained** and all evidence you need is **already preserved** — eradication destroys artefacts.
> 2. Ensure you have authorized scope and change-control approval for rebuild, restore and credential changes.
> 3. Validate state-changing actions with `-WhatIf` / `--dry-run` first, and stage changes before fleet-wide application.
> 4. Document every eradication and recovery action in the incident ticket.
> 5. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The sequence below follows the **NIST SP 800-61r2 §3.3.4 (Eradication and Recovery)** and **SANS
    PICERL** incident-handling phases cited at the foot of this page, and links to the project's own
    verified playbooks for each action, but has **not** been lab-run end to end for this page.
    Rebuilding, restoring from backup and rotating credentials **can cause outages and data loss** if
    sequenced wrongly or if a backup predates the intrusion — stage each step, validate backups are
    clean and pre-compromise, and confirm service health before full return. Remove this block when
    `verified: true`.

This is the **back half of the incident-response lifecycle**: Containment has stopped the bleeding, and
now the threat is fully removed, the way in is closed, and clean systems are returned to service. It sits
between [Automated Multi-Vector Containment](automated-containment.md) and
[Post-Incident Activity and Lessons Learned](post-incident-lessons-learned.md).

**Trigger:** the incident is contained (host isolated, sessions revoked, indicators blocked) and the
investigation has scoped the full extent of the compromise.

**Goal:** remove every attacker foothold, persistence mechanism and malware; close the initial entry
vector; and return validated, re-hardened systems to production without reinfection.

## 1. Confirm containment holds and evidence is preserved

Eradication is destructive to forensic artefacts. Before you remove anything, confirm containment is
still in effect and that memory, disk and log evidence is already captured.

→ [Automated Multi-Vector Containment](automated-containment.md) · [Ransomware Host Isolation](ransomware-host-isolation.md) · [Live Memory Acquisition](../forensics/memory-acquisition-analysis.md) · [Windows Disk Artifacts](../forensics/windows-disk-artifacts.md) · [Linux Live Response](../forensics/linux-live-response-forensics.md)

## 2. Enumerate everything that must be eradicated

Build the full removal list from the investigation: malware and dropped files, persistence (services,
scheduled tasks/cron, run keys, WMI subscriptions), attacker-created accounts, added credentials and
tokens, and any C2 reachable from the estate. If the scope is unclear, **do not** declare eradication
complete — resolve the unknown first.

→ [Malware Triage](malware-triage.md) · [Scheduled Task and Cron Persistence Review](../threat-hunting/scheduled-task-persistence-review.md) · [Network and PCAP Forensics](../forensics/network-pcap-forensics.md)

## 3. Remove persistence and malware — decide clean-in-place vs rebuild

| Situation | Action |
| --- | --- |
| Single known file, no execution, no persistence | Quarantine/remove, confirm, keep under watch |
| Executed, persistence/C2 found, scope fully understood | Remove each foothold, full scan, re-verify — or rebuild if trust is in doubt |
| Root/SYSTEM/domain compromise, rootkit, or incomplete scope | **Rebuild/reimage from known-good media** — do not trust a cleaned host |

→ [Malware Triage](malware-triage.md) · [Endpoint Triage](endpoint-triage.md)

> [!CAUTION]
> When you cannot *prove* the host is clean, rebuild. A missed persistence mechanism re-admits the
> attacker and re-opens the whole incident.

## 4. Close the initial entry vector

Removing the malware does not close the door it came through. Patch the exploited vulnerability, fix the
misconfiguration, block the delivery sender/URL, or revoke the abused grant — whichever was the initial
access. Confirm the vector is closed before returning the asset.

→ [Investigation Playbook — Azure Resource Hijacking](azure-resource-hijacking.md) · [Account Compromise Investigation](account-compromise.md) · [Hardening](../hardening/index.md)

## 5. Eradicate compromised credentials and identity footholds

Any credential, key, token or secret exposed on a compromised host or identity is burned. Rotate in
dependency order and revoke attacker-added authentication (added keys, app secrets, MFA methods,
service principals).

→ [Credential Rotation After a Compromise](credential-rotation-after-compromise.md)

## 6. Recover — validated restore from backup, or rebuild from known-good media

Choose per asset: reimage/rebuild from trusted media, or restore from a backup **taken before the
intrusion** and verified clean. Validate the restore point against the incident timeline so you do not
reintroduce the implant.

→ [Backup and Recovery — Job Verification](../administration/backup-and-recovery.md#2-backup-job-verification) · [BitLocker Recovery](../administration/bitlocker-recovery.md)

```powershell
# After a restore/rebuild, confirm no known persistence remains before reconnecting.
# -WhatIf where a cmdlet supports it; this block only READS.
Get-ScheduledTask | Where-Object State -ne 'Disabled' |
    Select-Object TaskName, TaskPath, @{n='Action';e={$_.Actions.Execute}}
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
```

```bash
# Linux: confirm no attacker cron/systemd persistence survived the restore (read-only)
for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done
systemctl list-unit-files --state=enabled --type=service
```

## 7. Re-harden before you return the asset

Restore the asset to a **better** state than before the incident — never back to the configuration that
was compromised. Apply the relevant hardening baseline and close the finding class that let the incident
happen.

→ [Hardening](../hardening/index.md) · [Credential Rotation After a Compromise](credential-rotation-after-compromise.md)

## 8. Staged return to production with heightened monitoring

Return in stages, watching for recurrence of the attacker's TTPs. Ensure telemetry is flowing from the
recovered asset, and add or tune detection for exactly what was observed so the same activity alerts
immediately if it returns.

→ [Sysmon Deployment and Tuning](../administration/sysmon-deployment-tuning.md#5-health-monitoring-minifilter-driver-altitude) · [Centralized Log Forwarding (WEF / rsyslog)](../administration/centralized-log-forwarding-wef-rsyslog.md) · [Detection Development Lifecycle](../detection-engineering/detection-development-lifecycle.md) · [Alert Tuning and False Positive Management](../detection-engineering/alert-tuning-false-positive-management.md)

## 9. Exit criteria — when eradication and recovery is complete

- Every enumerated foothold, persistence mechanism and malware artefact is removed or rebuilt away.
- The initial entry vector is closed and confirmed.
- All exposed credentials are rotated; attacker-added authentication is revoked.
- Recovered assets are re-hardened, monitored, and stable in production for the agreed watch window with
  no sign of recurrence.

When these hold, move to the final lifecycle phase.

→ [Post-Incident Activity and Lessons Learned](post-incident-lessons-learned.md)

## Related

- [Automated Multi-Vector Containment](automated-containment.md)
- [Ransomware Host Isolation](ransomware-host-isolation.md)
- [Credential Rotation After a Compromise](credential-rotation-after-compromise.md)
- [Malware Triage](malware-triage.md)
- [Post-Incident Activity and Lessons Learned](post-incident-lessons-learned.md)

## External Resources & White Papers

- [NIST SP 800-61r2 — Computer Security Incident Handling Guide (§3.3.4 Eradication and Recovery)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [NIST SP 800-184 — Guide for Cybersecurity Event Recovery](https://csrc.nist.gov/publications/detail/sp/800-184/final)
- [SANS — Incident Handler's Handbook (PICERL)](https://www.sans.org/white-papers/33901/)
- [CISA — Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks)
