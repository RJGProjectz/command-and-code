<#
.SYNOPSIS
    Automated CIS Microsoft Windows Benchmark Compliance Auditor (Level 1 & Level 2).
.DESCRIPTION
    Audits the local Windows host against critical CIS Benchmark recommendations
    across Account Policies, User Rights, Security Options, Advanced Audit Policy,
    Windows Defender Firewall, and Attack Surface Reduction.
.PARAMETER OutputJson
    Optional file path to export full structured JSON audit results.
.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1
.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -OutputJson "C:\Reports\cis_audit.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputJson
)

$ErrorActionPreference = "SilentlyContinue"
$AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "   COMMAND & CODE - CIS WINDOWS BENCHMARK AUDIT ENGINE        " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "Target Host : $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Timestamp   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Export Active Security Policy via Secedit (Account Policies & User Rights)
# ---------------------------------------------------------------------------
$SecExport = Join-Path $env:TEMP "cis_temp_audit.inf"
secedit.exe /export /cfg $SecExport /areas SECURITYPOLICY USER_RIGHTS | Out-Null
$SecText = if (Test-Path $SecExport) { Get-Content $SecExport -Raw } else { "" }
Remove-Item $SecExport -Force -ErrorAction SilentlyContinue

function Add-AuditResult {
    param(
        [string]$CisId,
        [string]$Category,
        [string]$Description,
        [bool]$Compliant,
        [string]$ObservedValue,
        [string]$ExpectedValue
    )
    $status = if ($Compliant) { "PASS" } else { "FAIL" }
    $color = if ($Compliant) { "Green" } else { "Red" }
    
    $AuditResults.Add([PSCustomObject]@{
        CisId         = $CisId
        Category      = $Category
        Description   = $Description
        Status        = $status
        Compliant     = $Compliant
        ObservedValue = $ObservedValue
        ExpectedValue = $ExpectedValue
    })
    
    Write-Host "[$status] $CisId - $Description" -ForegroundColor $color
    Write-Host "       Observed: $ObservedValue | Required: $ExpectedValue" -ForegroundColor Gray
}

# --- CIS Section 1: Account Policies ---
$PassLen = if ($SecText -match 'MinimumPasswordLength\s*=\s*(\d+)') { [int]$Matches[1] } else { 0 }
Add-AuditResult -CisId "CIS 1.1.4" -Category "Account Policies" -Description "Minimum Password Length >= 14" `
    -Compliant ($PassLen -ge 14) -ObservedValue "$PassLen chars" -ExpectedValue ">= 14 chars"

$Lockout = if ($SecText -match 'LockoutBadCount\s*=\s*(\d+)') { [int]$Matches[1] } else { 0 }
Add-AuditResult -CisId "CIS 1.2.2" -Category "Account Policies" -Description "Account Lockout Threshold <= 5" `
    -Compliant ($Lockout -gt 0 -and $Lockout -le 5) -ObservedValue "$Lockout attempts" -ExpectedValue "1 to 5 attempts"

# --- CIS Section 2: User Rights Assignment ---
$DebugPriv = if ($SecText -match 'SeDebugPrivilege\s*=\s*([^\r\n]+)') { $Matches[1].Trim() } else { "None" }
Add-AuditResult -CisId "CIS 2.2.14" -Category "User Rights" -Description "SeDebugPrivilege restricted to Administrators" `
    -Compliant ($DebugPriv -eq "*S-1-5-32-544" -or $DebugPriv -eq "None") -ObservedValue $DebugPriv -ExpectedValue "Administrators (*S-1-5-32-544)"

$DenyNet = if ($SecText -match 'SeDenyNetworkLogonRight\s*=\s*([^\r\n]+)') { $Matches[1].Trim() } else { "None" }
Add-AuditResult -CisId "CIS 2.2.21" -Category "User Rights" -Description "SeDenyNetworkLogonRight includes Guests" `
    -Compliant ($DenyNet -match 'S-1-5-32-546') -ObservedValue $DenyNet -ExpectedValue "Includes Guests (S-1-5-32-546)"

# --- CIS Section 2.3: Security Options (Registry) ---
$LsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$LmCompat = (Get-ItemProperty -Path $LsaKey -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
Add-AuditResult -CisId "CIS 2.3.11.1" -Category "Security Options" -Description "NTLMv2 only (LmCompatibilityLevel = 5)" `
    -Compliant ($LmCompat -eq 5) -ObservedValue "$LmCompat" -ExpectedValue "5"

$RestAnon = (Get-ItemProperty -Path $LsaKey -Name "RestrictAnonymous" -ErrorAction SilentlyContinue).RestrictAnonymous
Add-AuditResult -CisId "CIS 2.3.11.4" -Category "Security Options" -Description "Restrict Anonymous SAM & Share Enumeration" `
    -Compliant ($RestAnon -ge 1) -ObservedValue "$RestAnon" -ExpectedValue ">= 1"

$UacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$PromptSecure = (Get-ItemProperty -Path $UacKey -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop
Add-AuditResult -CisId "CIS 2.3.17.5" -Category "Security Options" -Description "UAC: Prompt on Secure Desktop" `
    -Compliant ($PromptSecure -eq 1) -ObservedValue "$PromptSecure" -ExpectedValue "1"

# --- CIS Section 9: Windows Defender Firewall ---
$FwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($p in $FwProfiles) {
    $isBlock = ($p.Enabled -eq "True" -and $p.DefaultInboundAction -eq "Block")
    Add-AuditResult -CisId "CIS 9.$($p.Name)" -Category "Firewall" -Description "Firewall $($p.Name) Profile: Default Inbound Block" `
        -Compliant $isBlock -ObservedValue "Enabled=$($p.Enabled), Inbound=$($p.DefaultInboundAction)" -ExpectedValue "Enabled=True, Inbound=Block"
}

# --- CIS Section 17: Advanced Audit Policy ---
$AuditCsv = auditpol.exe /get /category:* /r | ConvertFrom-Csv
function Check-AuditSubcategory {
    param([string]$CisId, [string]$SubcategoryName)
    $row = $AuditCsv | Where-Object { $_.'Subcategory Name' -eq $SubcategoryName }
    $setting = if ($row) { $row.'Inclusion Setting' } else { "No Auditing" }
    $isComp = ($setting -ne "No Auditing" -and $setting -ne "Not Configured")
    Add-AuditResult -CisId $CisId -Category "Audit Policy" -Description "Audit $SubcategoryName" `
        -Compliant $isComp -ObservedValue $setting -ExpectedValue "Success / Failure"
}

Check-AuditSubcategory -CisId "CIS 17.1.1" -SubcategoryName "Credential Validation"
Check-AuditSubcategory -CisId "CIS 17.3.1" -SubcategoryName "Process Creation"
Check-AuditSubcategory -CisId "CIS 17.5.5" -SubcategoryName "Logon"
Check-AuditSubcategory -CisId "CIS 17.5.6" -SubcategoryName "Special Logon"
Check-AuditSubcategory -CisId "CIS 17.8.1" -SubcategoryName "Sensitive Privilege Use"

# Check CommandLine in Event 4688
$AuditSysKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$CmdLineInc = (Get-ItemProperty -Path $AuditSysKey -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Add-AuditResult -CisId "CIS 17.3.2" -Category "Audit Policy" -Description "Process Creation Include CommandLine (Event 4688)" `
    -Compliant ($CmdLineInc -eq 1) -ObservedValue "$CmdLineInc" -ExpectedValue "1"

# --- CIS Section 18: Administrative Templates ---
$RunAsPPL = (Get-ItemProperty -Path $LsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
Add-AuditResult -CisId "CIS 18.3.1" -Category "Administrative Templates" -Description "LSA Protection (RunAsPPL = 1)" `
    -Compliant ($RunAsPPL -ge 1) -ObservedValue "$RunAsPPL" -ExpectedValue "1"

$SmbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
Add-AuditResult -CisId "CIS 18.9.79" -Category "Protocols" -Description "SMBv1 Protocol Disabled" `
    -Compliant ($SmbConfig.EnableSMB1Protocol -eq $false) -ObservedValue "SMB1=$($SmbConfig.EnableSMB1Protocol)" -ExpectedValue "SMB1=False"

# --- Summary Statistics ---
$Total = $AuditResults.Count
$Passed = ($AuditResults | Where-Object { $_.Compliant -eq $true }).Count
$Failed = $Total - $Passed
$Score = if ($Total -gt 0) { [math]::Round(($Passed / $Total) * 100, 1) } else { 0 }

Write-Host ""
Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "CIS AUDIT SUMMARY: $Passed / $Total Passed ($Score% Compliant)" -ForegroundColor $(if ($Score -ge 80) { "Green" } else { "Yellow" })
Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan

if ($OutputJson) {
    $AuditReport = [PSCustomObject]@{
        ComputerName   = $env:COMPUTERNAME
        TimestampUtc   = (Get-Date).ToUniversalTime().ToString("o")
        TotalEvaluated = $Total
        Passed         = $Passed
        Failed         = $Failed
        CompliancePct  = $Score
        Results        = $AuditResults
    }
    $AuditReport | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputJson -Encoding utf8
    Write-Host "Full JSON audit report saved to: $OutputJson" -ForegroundColor Cyan
}

return $AuditResults
