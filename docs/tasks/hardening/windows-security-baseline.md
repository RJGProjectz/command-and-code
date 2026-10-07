---
title: Windows Security Baseline — CIS Benchmark & NIST CSF 2.0
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
tasks:
  - Hardening
  - Assurance
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - cis-benchmark
  - nist-csf
  - baseline
  - hardening
  - windows-server
  - attack-surface-reduction
  - lsa-protection
---

# Windows Security Baseline — CIS Benchmark & NIST CSF 2.0

Hardened operational baseline configurations for enterprise Windows workstations and Windows Server environments, aligned with the **CIS Microsoft Windows Server Benchmark (Level 1 & Level 2)** and **NIST Cybersecurity Framework (CSF) 2.0** (`PR.PS-01`, `PR.AC-01`, `PR.DS-01`, `DE.CM-01`).

---

## 1. Compliance Alignment Matrix

| CIS Control | NIST CSF 2.0 | Configuration Target | Hardening Standard |
|:---|:---|:---|:---|
| **CIS 1.1** | `PR.AC-01` | Account Lockout Policy | Lockout threshold: 5 invalid attempts; duration: 30 mins; reset: 30 mins. |
| **CIS 2.3** | `PR.AC-04` | User Rights Assignment | Deny network logon and Remote Desktop Services to guest accounts. |
| **CIS 18.3** | `PR.PS-01` | LSA Protection (`RunAsPPL`) | Protect LSASS process against memory dumping by unauthorized debuggers. |
| **CIS 18.9** | `PR.DS-01` | Network Protocols | Disable legacy SMBv1, NetBIOS, and LLMNR broadcast name resolution. |
| **CIS 17.5** | `DE.CM-01` | Advanced Audit Policy | Audit Process Creation (with command-line logging) and PowerShell Script Blocks. |
| **CIS 18.4** | `PR.PS-06` | Attack Surface Reduction (ASR) | Block credential stealing from LSASS and child processes spawned by Office. |

---

## 2. Core Operating System Hardening Script

```powershell
# Set-ExecutionPolicy Unrestricted -Scope Process
# Execute within an elevated Administrator PowerShell session

Write-Host "Applying Windows Enterprise Hardening Baseline..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Disable Legacy Protocols (SMBv1, LLMNR) [CIS 18.9.79 / NIST PR.DS-01]
# ---------------------------------------------------------------------------
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EncryptData $true -Force

# Disable LLMNR on all network adapters
$dnsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (!(Test-Path $dnsPath)) { New-Item -Path $dnsPath -Force | Out-Null }
Set-ItemProperty -Path $dnsPath -Name "EnableMulticast" -Value 0 -Type DWord

# ---------------------------------------------------------------------------
# 2. Enforce LSA Protection & Credential Guard [CIS 18.3.1 / NIST PR.AC-01]
# ---------------------------------------------------------------------------
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord
Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord # Send NTLMv2 only, refuse LM & NTLM

# ---------------------------------------------------------------------------
# 3. Restrict Remote Desktop Security (NLA Enforced) [CIS 18.9.58]
# ---------------------------------------------------------------------------
$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -Type DWord # Require NLA
Set-ItemProperty -Path $rdpPath -Name "MinEncryptionLevel" -Value 3 -Type DWord # High encryption

# ---------------------------------------------------------------------------
# 4. Enable Advanced Command-Line Process Auditing [CIS 17.5.1 / NIST DE.CM-01]
# ---------------------------------------------------------------------------
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (!(Test-Path $auditPath)) { New-Item -Path $auditPath -Force | Out-Null }
Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Enable Script Block Logging (Event 4104)
$psAuditPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $psAuditPath)) { New-Item -Path $psAuditPath -Force | Out-Null }
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

Write-Host "Core OS hardening applied successfully." -ForegroundColor Green
```

---

## 3. Microsoft Defender Attack Surface Reduction (ASR) Rules

Configure Microsoft Defender ASR rules in **Block** mode (`1`) using PowerShell:

```powershell
# Essential Enterprise ASR Rules
$AsrRules = @{
    # Block credential stealing from Windows Local Security Authority Subsystem (LSASS)
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1
    # Block executable content from email client and webmail
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1
    # Block Office applications from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1
    # Block Office applications from injecting code into other processes
    "756346d7-0957-498c-a4b1-b76ac47fd73d" = 1
    # Block obfuscated scripts (JS, VBS, PS)
    "5beb0a2d-9a0a-4a09-96da-42993b5a6ddb" = 1
    # Block untrusted and unsigned processes that run from USB
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1
}

$ruleIds = [string[]]$AsrRules.Keys
$ruleActions = [string[]]$AsrRules.Values

Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $ruleActions
Write-Host "Configured $($ruleIds.Count) ASR rules in Block Mode." -ForegroundColor Green
```

---

## 4. Verification & Audit Commands

```powershell
# Verify LSA Protection status
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RunAsPPL

# Verify SMBv1 is disabled
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EncryptData

# Inspect active ASR rules on local host
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids

# Check command line inclusion in 4688 events
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit").ProcessCreationIncludeCmdLine_Enabled
```
