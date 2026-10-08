---
title: Windows Security Baseline — CIS Benchmark & NIST CSF 2.0
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - CMD
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

## 1. CIS Windows Server Benchmark Architecture (Level 1 & Level 2)

The **CIS Microsoft Windows Server Benchmark** organizes enterprise hardening across 19 distinct functional sections. Command & Code provides dedicated operational implementation guides for the most complex domains:

* **[User Rights Assignment & Account Policies](windows-cis-user-rights-assignment.md):** Password aging, lockout thresholds, Kerberos tickets, and restricting `SeDebugPrivilege`, `SeImpersonatePrivilege`, and `SeNetworkLogonRight`.
* **[Advanced Audit Policy Baseline](windows-cis-advanced-audit-policy.md):** Full 50+ subcategory audit policy configuration across the 9 audit categories via `auditpol.exe`.
* **[Attack Surface Reduction (ASR) & Credential Guard](windows-cis-attack-surface-reduction.md):** Complete 16-rule ASR block-mode configuration, Virtualization-Based Security (VBS), and Windows Defender Firewall baseline.
* **[Active Directory Kerberos & LDAP Protocol Hardening](ad-kerberos-ldap-hardening.md):** Group Managed Service Accounts (gMSA), LDAP signing (`LDAPServerIntegrity = 2`), and RC4 deprecation.

### Compliance Alignment Matrix

| CIS Section | Domain | Configuration Target | Hardening Standard |
|:---|:---|:---|:---|
| **Section 1** | Account Policies | Password & Lockout | Minimum 14 chars, lockout after 5 attempts for 15 mins. |
| **Section 2** | User Rights Assignment | Privilege Elevation | Restrict `SeDebugPrivilege` and `SeImpersonatePrivilege` to Administrators/Services. |
| **Section 2.3** | Security Options | LSA & UAC | RunAsPPL = 1, UAC Secure Desktop, Restrict Anonymous SAM. |
| **Section 9** | Defender Firewall | Network Boundaries | Block inbound, allow outbound, dropped packet logging enabled. |
| **Section 17** | Advanced Audit Policy | Security Telemetry | Subcategory auditing for Process Creation, Logons, and Privilege Use. |
| **Section 18.3** | Hardware Security | Credential Guard | Enable Virtualization-Based Security (VBS) with UEFI lock. |
| **Section 18.4** | Exploit Mitigation | Defender ASR | Enforce all 16 ASR rules in Block Mode (`1`). |
| **Section 18.9** | Network Protocols | Attack Surface | Disable SMBv1, NetBIOS, LLMNR, and enforce RDP NLA. |

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

---

## 5. Windows CMD Baseline Operations

Native Command Prompt commands for applying and validating security baselines without PowerShell:

### Account Policies & Lockouts (`net accounts`)

```bat
:: Enforce lockout after 5 invalid attempts with 30-minute lockout duration
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

:: Verify active account policies
net accounts
```

### Registry Hardening via CMD (`reg.exe`)

```bat
:: Enable LSA Protection (RunAsPPL) [CIS 18.3 / NIST PR.PS-01]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

:: Disable LLMNR multicast name resolution across adapters [CIS 18.9 / NIST PR.DS-01]
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f

:: Include full process command-line in Event ID 4688 logs [CIS 17.5 / NIST DE.CM-01]
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

:: Prevent anonymous SID/Name enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
```

### Advanced Audit Policy Enforcement (`auditpol.exe`)

```bat
:: Audit successful and failed logons (4624, 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Audit process creation events (4688)
auditpol /set /subcategory:"Process Creation" /success:enable

:: Audit user rights assignment and privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

:: Query current audit configuration
auditpol /get /category:*
```

### Host Firewall Enforcement (`netsh.exe`)

```bat
:: Enforce default-deny inbound posture across all firewall profiles
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

:: Enable firewall logging for dropped connections
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging filename "%SystemRoot%\system32\logfiles\firewall\pfirewall.log"
```

