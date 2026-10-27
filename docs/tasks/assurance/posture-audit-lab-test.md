---
title: Posture Audit Lab - Bundle and Retrieve Reports Without WinRM
type: workflow
platforms: [Windows, Windows Server, Active Directory]
languages: [PowerShell]
tasks: [Assurance, Hardening, Administration]
category: Workflow
security_domain: Compliance
author: RJGProjectz
date_created: 2026-10-26
last_updated: 2026-10-26
tags: [posture, cis-benchmark, active-directory, evidence-collection, smb, scp, usb, air-gapped, no-winrm, read-only, ndjson, compliance]
aliases: [posture audit lab, posture evidence collection, export posture bundle, collect posture reports, retrieve audit reports without winrm, posture audit smb scp usb, offline posture audit]
difficulty: intermediate
verified: false
---

# Posture Audit Lab - Bundle and Retrieve Reports Without WinRM

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Every script in this workflow is **read-only** with respect to the audited host's configuration and
> uses **no PowerShell remoting, no `Invoke-Command`, no `New-PSSession` and no WinRM**. Reports list
> users, policy settings and weaknesses, so treat the bundles as sensitive evidence. Run the audit
> from an **elevated** PowerShell on each target and retrieve the files only to a trusted worker.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The scripts and this runbook are **doc-checked** against the posture-audit tooling and the SMB /
    SCP / local transports, but have **not** been lab-run end to end across a real workstation, member
    server and domain controller. Verify the retrieval on a test asset before relying on it for an
    audit of record.

**Trigger:** you have run, or plan to run, [`Invoke-PostureAudit.ps1`](posture-audit.md) on several
assets (a workstation, a member server, a domain controller) and need to gather every report back to
one jumpstation or laptop - but PSRemoting/WinRM is disabled in the environment (the owner's
requirement).

**Goal:** run the audit locally on each target, bundle its reports into one zip + manifest with
`Export-PostureBundle.ps1`, and pull every bundle back to a worker with `Collect-PostureReports.ps1`
over SMB, SSH/SCP or physical media - never touching WinRM.

## Why no WinRM

The audit always runs **locally** on the endpoint and writes its reports into the script's own folder
(`-OutputPath` defaults to `$PSScriptRoot`), so there is no remote-execution step to secure. Retrieval
is then a plain **file copy**, which needs only a file transport that is already open in most networks:
the SMB admin share, OpenSSH/`scp`, or a USB stick for an air-gapped host. This keeps the attack
surface tiny and works where `winrm quickconfig` was never run.

| Report | Written by | Pattern |
| :--- | :--- | :--- |
| Launcher (OS + AD merged) | `Invoke-PostureAudit.ps1` | `posture-<HOST>-<UTC>.{json,ndjson,csv}` |
| AD environment posture | `Invoke-AdPostureAudit.ps1` | `adposture-<HOST>-<UTC>.*` |
| Standalone CIS OS audit | CIS audit tool | `cis-<HOST>-<LEVEL>-<UTC>.*` |
| **Bundle + manifest** | `Export-PostureBundle.ps1` | `posture-bundle-<HOST>-<UTC>.zip` / `.manifest.json` |

## Prerequisites

1. **On each target:** the repo's `scripts/powershell` folder (keep its relative layout - the launcher
   resolves `..\cis\catalogs` from its own folder). Open an **elevated** PowerShell so `secedit` /
   `auditpol` can read account, user-rights and audit-policy settings.
2. **On a domain controller / management host:** the RSAT **ActiveDirectory** module
   (`Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`, or
   `Install-WindowsFeature RSAT-AD-PowerShell` on Server). On a DC the AD posture runs automatically.
3. **On the worker:** for SMB, rights to the target's admin share (or a `-Credential`); for SCP, the
   OpenSSH client (`scp.exe`) and SSH access; for Local, the USB/mounted path.

## Step 1 - Run the audit locally on each target

Run on each asset in turn. The audit is read-only in both `-TargetEnvironment Test` (default) and
`Prod`.

```powershell
# Workstation or member server (elevated)
.\Invoke-PostureAudit.ps1 -Level L1

# Management host / DC - add -IncludeAd off a DC only if auto-detection is skipped
.\Invoke-PostureAudit.ps1 -IncludeAd
```

This leaves `posture-<HOST>-<UTC>.json/.ndjson/.csv` (and `adposture-*` on a DC) beside the script.

## Step 2 - Bundle the reports with Export-PostureBundle.ps1

Still on the target, zip the reports into one artifact and a manifest. `-RunAudit` runs the launcher
first if it is present, so one command both audits and bundles:

```powershell
# Bundle whatever reports already exist in this folder
.\Export-PostureBundle.ps1

# Audit first, then bundle only the newest set per report type
.\Export-PostureBundle.ps1 -RunAudit -Latest

# Collect from a staging folder and drop the bundle straight onto a USB drive
.\Export-PostureBundle.ps1 -SourcePath D:\Evidence -OutputPath E:\
```

You get `posture-bundle-<HOST>-<UTC>.zip` plus `posture-bundle-<HOST>-<UTC>.manifest.json`. The
manifest records the host, UTC, the file list, and the pass/fail/score pulled from the newest
`posture-*.json` / `adposture-*.json` summary:

```json
{
  "schema": "cc.posture.bundle/1",
  "host": "SRV01",
  "timestamp": "2026-10-26T18:30:00Z",
  "fileCount": 3,
  "files": ["posture-SRV01-20261026T183000Z.json", "...ndjson", "...csv"],
  "summary": { "pass": 180, "fail": 12, "scorePct": 93.8 }
}
```

A previous `posture-bundle-*` is never swept into a new bundle, so re-running is safe.

## Step 3 - Retrieve every bundle to the worker

From the jumpstation/laptop, pull the files into `posture-evidence\<host>\`. Pick the transport that
is open in your environment - all three are **read-only pulls** that run nothing on the endpoint.

### SMB (admin share)

```powershell
# Same share on each asset; {asset} is not needed - the asset name fills the UNC host
.\Collect-PostureReports.ps1 -Asset SRV01,SRV02,DC01 `
    -Method Smb -RemotePath 'C$\Tools\PostureAudit\scripts\powershell'

# With explicit credentials (mounts the share via New-PSDrive, then copies)
$cred = Get-Credential
.\Collect-PostureReports.ps1 -Asset SRV01 -Method Smb `
    -RemotePath 'C$\Tools\PostureAudit\scripts\powershell' -Credential $cred
```

### SSH / SCP

```powershell
# Shells out to scp.exe: <SshUser>@<asset>:<RemotePath>/<pattern> -> posture-evidence\<asset>\
.\Collect-PostureReports.ps1 -Asset dc01.lab.local `
    -Method Scp -SshUser labadmin -RemotePath '/opt/postureaudit'
```

### Local / USB / mounted path

```powershell
# After an air-gapped copy to a USB drive
.\Collect-PostureReports.ps1 -Asset WKSTN07 -Method Local -RemotePath 'E:\'

# A per-asset NAS layout - {asset} is substituted for each name
.\Collect-PostureReports.ps1 -Asset WKSTN07,WKSTN08 `
    -Method Local -RemotePath '\\nas\evidence\{asset}'
```

Unreachable assets are **warned about and skipped** - the run continues to the next asset and returns
one result object per asset (`Status` = `ok` / `unreachable` / `error`, with `FilesCopied`).

## Where the files land

```text
posture-evidence\
  SRV01\   posture-SRV01-*.json/.ndjson/.csv   posture-bundle-SRV01-*.zip + .manifest.json
  SRV02\   ...
  DC01\    posture-DC01-*.*   adposture-DC01-*.*   posture-bundle-DC01-*.*
```

Each asset keeps its own sub-folder, so evidence never collides and the manifest tells you at a glance
which host scored what.

## Step 4 - Consume the evidence in a homelab

- **SIEM (Splunk / Sentinel / S1):** ingest the `*.ndjson` - one JSON line per check with the shared
  base fields (`timestamp`, `host`, `action`, `result`, `title`, ...), so a homelab SIEM can trend
  pass/fail over time and alert on regressions without parsing.
- **Spreadsheet / quick review:** open the `*.csv` per host.
- **Programmatic / diff:** the `*.json` carries the full `cc.posture.report/1` object (summary +
  per-check results); the bundle `*.manifest.json` (`cc.posture.bundle/1`) gives a one-line pass/fail
  score per host for a roll-up across the fleet.

## See also

- [Posture Audit - One-Command Workstation, Server & AD](posture-audit.md) - the launcher these scripts bundle and retrieve.
- [AD Environment Posture Audit](ad-environment-posture-audit.md) - the STIG / CIS / best-practice crosswalk engine behind `adposture-*`.
- [CIS Hardening Lab Test](../hardening/cis-hardening-lab-test.md) - before/after diff of CIS reports with `FUNC_PS_COMPARE_CIS_REPORT.ps1`.
