---
title: Exchange Online
platforms: [Microsoft 365, Exchange Online]
languages: [PowerShell]
tasks: [Incident Response, Investigation, Administration]
category: Email
tags: [exchange online, inbox rules, forwarding, message trace, unified audit log, bec]
aliases: [inbox rules, mail forwarding, message trace, Search-UnifiedAuditLog, business email compromise, block sender]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Exchange Online

Uses the **ExchangeOnlineManagement** module (`Install-Module ExchangeOnlineManagement`).

```powershell
Connect-ExchangeOnline -UserPrincipalName <ADMIN_USER>@<DOMAIN>
```

## Inbox rules on a mailbox

Malicious rules that forward, delete or hide mail are the most common business-email-compromise persistence ([T1564.008](https://attack.mitre.org/techniques/T1564/008/)).

```powershell
Get-InboxRule -Mailbox '<USER>@<DOMAIN>' |
    Select-Object Name, Enabled, Priority, From, SubjectContainsWords, BodyContainsWords,
                  ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder, MarkAsRead
```

**What to look for:** rules named `.`, `..` or similar; rules moving mail to *RSS Feeds*, *Archive* or *Conversation History*; keyword filters like `invoice`, `payment`, `wire`, `bank`; any external `ForwardTo`/`RedirectTo`.

Remove after documenting:

```powershell
Get-InboxRule -Mailbox '<USER>@<DOMAIN>' -Identity 'RuleName' | Format-List * | Out-File C:\Cases\rule.txt
Remove-InboxRule -Mailbox '<USER>@<DOMAIN>' -Identity 'RuleName' -Confirm:$false
```

## Mailbox-level forwarding

```powershell
Get-Mailbox -ResultSize Unlimited |
    Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |
    Select-Object UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
```

## Mailbox permissions

```powershell
Get-MailboxPermission -Identity '<USER>@<DOMAIN>' |
    Where-Object { $_.User -notlike 'NT AUTHORITY\SELF' -and -not $_.IsInherited }
Get-RecipientPermission -Identity '<USER>@<DOMAIN>' | Where-Object Trustee -ne 'NT AUTHORITY\SELF'
```

## Message trace

```powershell
Get-MessageTraceV2 -SenderAddress '<ATTACKER>@<DOMAIN>' -StartDate (Get-Date).AddDays(-5) -EndDate (Get-Date) |
    Select-Object Received, SenderAddress, RecipientAddress, Subject, Status
```

`Get-MessageTraceV2` replaced `Get-MessageTrace`. It covers 90 days of history, with a maximum of 10 days per query. For older environments still on the previous cmdlet, swap the name — parameters are similar.

## Unified audit log

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -UserIds '<USER>@<DOMAIN>' -Operations 'New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules' -ResultSize 5000 |
    Select-Object CreationDate, UserIds, Operations, @{ Name = 'Detail'; Expression = { $_.AuditData } }
```

`AuditData` is JSON — parse it with `ConvertFrom-Json`. Rules created from Outlook clients appear as `UpdateInboxRules`; rules created with PowerShell or OWA as `New-InboxRule`.

## Block a sender tenant-wide

```powershell
New-TenantAllowBlockListItems -ListType Sender -Block -Entries '<ATTACKER>@<DOMAIN>' -NoExpiration
```

## Related

- [Account Compromise workflow](../../tasks/incident-response/account-compromise.md)
- [Entra ID](entra.md)

## Sources

- [Get-InboxRule](https://learn.microsoft.com/powershell/module/exchange/get-inboxrule)
- [Get-MessageTraceV2](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2)
- [Search-UnifiedAuditLog](https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog)
- [New-TenantAllowBlockListItems](https://learn.microsoft.com/powershell/module/exchange/new-tenantallowblocklistitems)
