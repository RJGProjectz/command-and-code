---
title: Microsoft 365
type: index
---

# Microsoft 365

Security administration and investigation for Defender XDR, Entra ID, Conditional Access, Intune and Exchange Online.

!!! info "Modules"
    Use the **Microsoft Graph PowerShell SDK** (`Microsoft.Graph`) and **ExchangeOnlineManagement**. The AzureAD and MSOnline modules are retired — do not build new automation on them.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Disable a user and revoke sessions | [Entra ID → Contain a compromised account](entra.md#contain-a-compromised-account) |
| Find malicious inbox rules | [Exchange → Inbox rules](exchange.md#inbox-rules-on-a-mailbox) |
| See why a sign-in was blocked | [Conditional Access](conditional-access.md#why-was-this-sign-in-blocked) |
| Run advanced hunting from a script | [Defender XDR](defender.md#run-an-advanced-hunting-query-from-powershell) |
| Check a device's join state | [Intune → dsregcmd](intune.md#check-device-join-and-enrollment-state) |

## All Microsoft 365 entries

<!-- cc:index platforms="Microsoft 365" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../../tasks/incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Conditional Access](conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Entra ID](entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Intune](intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [KQL Fundamentals](../../detection/kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [Microsoft Defender XDR and Defender for Endpoint](defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [PowerShell REST APIs](../../languages/powershell/rest-apis.md) | Entry | Windows, Microsoft 365, SentinelOne, Splunk | PowerShell | Automation, Incident Response |
| [Python HTTP and APIs](../../languages/python/http-apis.md) | Entry | Microsoft 365, SentinelOne, Splunk | Python | Automation, Incident Response |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |

<!-- /cc:index -->
