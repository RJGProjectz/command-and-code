---
title: Microsoft Purview and Unified Audit Log (UAL) Investigation
type: workflow
platforms:
  - Microsoft 365
  - Entra ID
  - Exchange Online
languages:
  - PowerShell
tasks:
  - Investigation
  - Incident Response
  - Forensics
verified: true
last_verified: 2026-10-07
difficulty: intermediate
tags:
  - microsoft-365
  - purview
  - unified-audit-log
  - exchange-online
  - forensic-investigation
  - search-unifiedauditlog
---

# Microsoft Purview and Unified Audit Log (UAL) Investigation

The Microsoft 365 Unified Audit Log ($UAL$) records events across Exchange Online, SharePoint, OneDrive, Microsoft Teams, and Entra ID. It is the primary forensic record for Business Email Compromise ($BEC$), data exfiltration, and cloud privilege abuse.

---

## 1. Connecting and Audit Log Prerequisites

Querying the UAL requires the `ExchangeOnlineManagement` module and the `View-Only Audit Logs` or `Audit Logs` role in Microsoft Purview.

```powershell
# 1. Connect to Exchange Online PowerShell V3
Connect-ExchangeOnline -UserPrincipalName admin@example.com

# 2. Verify that Unified Audit Logging is globally enabled
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

---

## 2. Investigating Business Email Compromise (BEC)

Attackers who breach a mailbox typically search for financial data, create forwarding rules, and access sensitive messages.

### A. Hunting Malicious Mailbox Forwarding Rules

```powershell
# Query for Inbox rule modifications in the last 7 days
$RulesEvents = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -Operations "New-InboxRule", "Set-InboxRule", "Enable-InboxRule" `
    -ResultSize 1000

# Parse JSON AuditData payload
$ParsedRules = foreach ($event in $RulesEvents) {
    $audit = $event.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
        CreationDate = $event.CreationDate
        UserId       = $event.UserIds
        Operation    = $event.Operations
        ClientIP     = $audit.ClientIPAddress
        RuleName     = $audit.Parameters | Where-Object { $_.Name -eq "Name" } | Select-Object -ExpandProperty Value
        ForwardTo    = $audit.Parameters | Where-Object { $_.Name -match "ForwardTo|RedirectTo" } | Select-Object -ExpandProperty Value
    }
}

$ParsedRules | Format-Table -AutoSize
```

### B. MailItemsAccessed (Proof of Compromise)

`MailItemsAccessed` is an advanced auditing action indicating whether an attacker actually opened or downloaded specific emails:

```powershell
# Search MailItemsAccessed for a compromised user
$MailAccess = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-3) -EndDate (Get-Date) `
    -Operations "MailItemsAccessed" `
    -FreeText "compromised_user@example.com" `
    -ResultSize 2000

$MailAccess | ForEach-Object {
    $audit = $_.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
        TimeCreated = $_.CreationDate
        ClientIP    = $audit.ClientIPAddress
        SessionId   = $audit.SessionId
        LogonType   = $audit.LogonType
        IsThrottled = $audit.OperationProperties | Where-Object { $_.Name -eq "IsThrottled" } | Select-Object -ExpandProperty Value
        FolderItems = ($audit.Folders.FolderItems | Measure-Object).Count
    }
} | Format-Table -AutoSize
```

---

## 3. Investigating File Exfiltration in SharePoint & OneDrive

Track mass file downloads or external sharing links:

```powershell
# Query FileDownloaded and FileShared events
$FileEvents = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-5) -EndDate (Get-Date) `
    -RecordType SharePointFileOperation `
    -Operations "FileDownloaded", "SharingSet", "AnonymousLinkCreated" `
    -ResultSize 3000

$FileEvents | ForEach-Object {
    $audit = $_.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
        Time       = $_.CreationDate
        User       = $_.UserIds
        Operation  = $_.Operations
        FileName   = $audit.SourceFileName
        SiteUrl    = $audit.SiteUrl
        ClientIP   = $audit.ClientIPAddress
    }
} | Where-Object { $_.Operation -eq "FileDownloaded" } |
    Group-Object User |
    Select-Object Name, Count |
    Sort-Object Count -Descending
```

---

## 4. Operational Investigation Gotchas

- **Telemetry Ingestion Latency**: UAL events typically appear within 15 to 60 minutes, but some services (SharePoint/Exchange) can take up to 24 hours under heavy load.
- **Audit Data Truncation**: PowerShell results cap at 5,000 events per query session. For enterprise investigations spanning hundreds of gigabytes of logs, pipe queries into an Azure Sentinel workspace or export via the Office 365 Management Activity API.
- **Retaining Audit Records**: Standard E3 licenses retain audit logs for 180 days; E5 / Microsoft Purview Audit (Premium) retains logs for up to 1 year (configurable up to 10 years).
