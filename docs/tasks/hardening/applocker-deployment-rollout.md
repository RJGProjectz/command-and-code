---
title: Hardening — AppLocker & Application Control Phased Enterprise Rollout
type: workflow
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
tasks:
  - Hardening
  - Administration
  - Assurance
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - applocker
  - application-whitelisting
  - hardening
  - clm
  - security-baseline
---

# Hardening — AppLocker & Application Control Phased Enterprise Rollout

A production deployment runbook for implementing Windows AppLocker application control without causing administrative lockouts or breaking line-of-business applications.

---

## 1. The 4-Phase Enterprise Rollout Lifecycle

Enforcing application control on Day 1 is the most common operational failure in endpoint management. Always follow a strict phased lifecycle:

```text
┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│    PHASE 1     │ ───► │    PHASE 2     │ ───► │    PHASE 3     │ ───► │    PHASE 4     │
│ Baseline Rules │      │   Audit Only   │      │ Telemetry Log  │      │ Enforcement &  │
│  & AppIDSvc    │      │ (No Blockings) │      │  Gap Analysis  │      │ Publisher Lock │
└────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘
```

- **Phase 1: Service Activation & Base Rules**: Enable the `AppIDSvc` service and generate baseline rules.
- **Phase 2: Audit-Only Mode**: Deploy via GPO with all rule collections configured to **Audit Only**.
- **Phase 3: Telemetry Harvesting**: Collect Event IDs 8003 (allowed in audit) and 8004 (would be blocked) to discover unapproved but legitimate business software.
- **Phase 4: Rule Hardening & Enforcement**: Transition collections to **Enforce** mode while eliminating user-writable path bypasses.

---

## 2. Phase 1: Service Activation & Baseline Policy Creation

AppLocker requires the **Application Identity (`AppIDSvc`)** service to evaluate process hashes and publisher signatures before process creation.

### Enable Application Identity Service via PowerShell
```powershell
# Set AppIDSvc to Automatic and start immediately
Set-Service -Name "AppIDSvc" -StartupType Automatic
Start-Service -Name "AppIDSvc"
Get-Service -Name "AppIDSvc" | Select-Object Name, Status, StartType
```

### Generate Default Base Rules
Default rules allow built-in Windows binaries and `Program Files` executables, plus full access for local `Administrators`:

```powershell
# Create baseline AppLocker XML with default rules for Executable and Script collections
$XmlPath = "$env:TEMP\AppLocker_Baseline.xml"

# Generate XML containing default allow rules
New-AppLockerPolicy -RuleType Path -User Everyone -DefaultRules -Xml > $XmlPath

# Inspect generated policy structure
Get-Content $XmlPath | Select-String -Pattern "<FilePathRule|<FilePublisherRule" | Select-Object -First 10
```

---

## 3. Phase 2: Deploy in Audit-Only Mode

Configure all rule collections (Executable, Script, Windows Installer, Packaged App) to **Audit Only**:

```powershell
# Load policy and enforce AuditOnly enforcement mode on all rule collections
[xml]$PolicyXml = Get-Content $XmlPath
$PolicyXml.AppLockerPolicy.RuleCollection | ForEach-Object {
    $_.SetAttribute("EnforcementMode", "AuditOnly")
}
$PolicyXml.Save("$env:TEMP\AppLocker_Audit.xml")

# Apply policy locally or export for Active Directory GPO import
Set-AppLockerPolicy -XmlPolicy "$env:TEMP\AppLocker_Audit.xml"
```

---

## 4. Phase 3: Telemetry Harvesting & Gap Analysis

While in Audit-Only mode, monitor the dedicated AppLocker event logs to discover software that would be blocked under enforcement:

| Event ID | Log Channel | Meaning |
| :--- | :--- | :--- |
| **8002** | `Microsoft-Windows-AppLocker/EXE and DLL` | Binary allowed by policy |
| **8003** | `Microsoft-Windows-AppLocker/EXE and DLL` | Binary would be BLOCKED under enforcement |
| **8004** | `Microsoft-Windows-AppLocker/MSI and Script` | Script / MSI would be BLOCKED under enforcement |

### Query Applications That Would Be Blocked
```powershell
# Query all would-be blocked executions across the past 14 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script'
    Id        = 8003, 8004
    StartTime = (Get-Date).AddDays(-14)
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventId     = $_.Id
        Path        = $_.Properties[2].Value
        User        = $_.Properties[1].Value
        RuleName    = $_.Properties[3].Value
    }
} | Group-Object Path | Select-Object Count, Name | Sort-Object Count -Descending
```

---

## 5. Phase 4: Path Bypass Hardening & Enforcement Switch

### Close User-Writable Windows Directory Bypasses
Default path rules permit `%WINDIR%\*`. Attackers exploit known subdirectories inside `C:\Windows` that standard users have write access to (e.g., `C:\Windows\Tasks`, `C:\Windows\Temp`, `C:\Windows\Tracing`):

```powershell
# Create explicit DENY rules for known user-writable Windows subfolders
$DenyPaths = @(
    "%WINDIR%\Tasks\*",
    "%WINDIR%\Temp\*",
    "%WINDIR%\Tracing\*",
    "%WINDIR%\Registration\CRMLog\*",
    "%WINDIR%\System32\spool\drivers\color\*"
)

# Prefer Publisher (code-signing) rules over Path rules whenever possible:
Get-AppLockerFileInformation -Directory "C:\Program Files\InternalApp\" |
    New-AppLockerPolicy -RuleType Publisher -User Everyone -Xml > "$env:TEMP\PublisherRules.xml"
```

### Script Rules & PowerShell Constrained Language Mode
Enforcing AppLocker **Script Rules** (`.ps1`, `.bat`) automatically forces interactive and script-based PowerShell sessions for non-administrators into **Constrained Language Mode (CLM)**, blocking access to arbitrary .NET reflection and Win32 APIs:

```powershell
# Verify current PowerShell language mode
$ExecutionContext.SessionState.LanguageMode
# Returns 'ConstrainedLanguage' when AppLocker Script Rules are enforced
```

### Switch Rule Collections to Enforce Mode
```powershell
# Load audited and tuned policy, switch enforcement to 'Enabled'
[xml]$FinalPolicy = Get-Content "$env:TEMP\AppLocker_Audit.xml"
$FinalPolicy.AppLockerPolicy.RuleCollection | ForEach-Object {
    $_.SetAttribute("EnforcementMode", "Enabled")
}
$FinalPolicy.Save("$env:TEMP\AppLocker_Enforced.xml")

# Apply final enforced policy
Set-AppLockerPolicy -XmlPolicy "$env:TEMP\AppLocker_Enforced.xml"
```

---

## 6. Emergency Rollback & Recovery Procedure

If an enforcement policy inadvertently blocks critical infrastructure processes, execute immediate administrative recovery:

```powershell
# 1. Clear local AppLocker policy cache and reset to permissive state
Clear-AppLockerPolicy

# 2. Or stop and disable the Application Identity service
Stop-Service -Name "AppIDSvc" -Force
Set-Service -Name "AppIDSvc" -StartupType Disabled
```

---

## Related Guides

- [Fundamentals — AppLocker & Application Control Baselines](../../fundamentals/systems/applocker.md)
- [Tasks — LOLBins Execution Hunting](../threat-hunting/lolbins-execution-hunting.md)
- [Windows Security Baseline (CIS/NIST)](windows-security-baseline.md)
- [System32 Native Executables Field Guide](../../languages/windows-cli/system32-toolkit.md)
