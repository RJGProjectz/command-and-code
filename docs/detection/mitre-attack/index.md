---
title: MITRE ATT&CK Mapping
type: reference
platforms: [Windows, Linux, Microsoft 365]
languages: [MITRE ATT&CK]
tasks: [Detection Engineering, Threat Hunting, Incident Response]
category: Reference
tags: [mitre, att&ck, techniques, mapping, coverage]
aliases: [attack technique, ttp mapping, T1059, T1053, T1547, detection coverage]
verified: true
last_verified: 2026-10-05
---

# MITRE ATT&CK Mapping

Techniques that entries in this manual help investigate or detect. Mappings are added only where they genuinely help — simple administrative commands are not mapped.

| Technique | Name | Investigate | Detect |
| --- | --- | --- | --- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | [Suspicious PowerShell](../../tasks/incident-response/suspicious-powershell.md) | [KQL](../kql/process-events.md#encoded-powershell) · [SPL](../spl/powershell.md) · [S1QL](../s1ql/hunting.md#encoded-or-download-cradle-powershell) · [Sigma](../sigma/examples.md#encoded-powershell-command-line) |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | [Bash decoding](../../languages/bash/text-processing.md#decode-base64-and-powershell-encoded-commands) | [KQL](../kql/process-events.md#encoded-powershell) |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | [KQL](../kql/file-registry-events.md#scheduled-task-creation) · [SPL](../spl/windows-events.md#scheduled-task-created-4698) · [Sigma](../sigma/examples.md#scheduled-task-created-by-command-line) |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | [Linux cron](../../platforms/linux/cron.md) | [S1QL](../s1ql/hunting.md#linux-cron-and-systemd-file-changes) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | [Suspicious Service](../../tasks/investigation/suspicious-service.md) | [KQL](../kql/file-registry-events.md#service-installation) · [SPL](../spl/windows-events.md#new-service-installed-7045) · [Sigma](../sigma/examples.md#suspicious-service-installation) |
| [T1543.002](https://attack.mitre.org/techniques/T1543/002/) | Systemd Service | [systemd persistence](../../platforms/linux/systemd.md#hunt-for-systemd-persistence) | — |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | [Registry Persistence](../../tasks/investigation/registry-persistence.md) | [KQL](../kql/file-registry-events.md#run-key-modifications) · [S1QL](../s1ql/hunting.md#run-key-writes) · [Sigma](../sigma/examples.md#run-key-persistence) |
| [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | Image File Execution Options Injection | [Windows registry](../../platforms/windows/registry.md#common-autostart-locations) | [KQL](../kql/file-registry-events.md#winlogon-and-ifeo-tampering) |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH Authorized Keys | [Linux SSH](../../platforms/linux/ssh.md#find-authorized-keys) | — |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | [Account Compromise](../../tasks/incident-response/account-compromise.md) | [KQL](../kql/logon-identity.md) |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | [Failed Authentication](../../tasks/investigation/failed-authentication.md) | [KQL](../kql/logon-identity.md#password-spray-against-entra-id) · [SPL](../spl/windows-events.md#failed-logons-4625) |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | [Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | [KQL](../kql/logon-identity.md#successful-rdp-logons) · [SPL](../spl/windows-events.md#rdp-logons-4624-logontype-10) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB / Windows Admin Shares | [Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | [SPL](../spl/network-dns.md#rdp-smb-between-workstations) |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol (C2) | [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | [KQL](../kql/network-events.md#possible-beaconing) · [SPL](../spl/network-dns.md#beaconing-by-interval-regularity) |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | [Suspicious Process](../../tasks/incident-response/suspicious-process.md) | [KQL](../kql/process-events.md#living-off-the-land-binaries-lolbins) |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | [Defender Exclusions](../../platforms/windows/defender.md#exclusions) · [EDR Agent Tampering](../spl/agent-tampering.md) | [KQL](../kql/file-registry-events.md#defender-exclusion-added) · [SPL](../spl/agent-tampering.md) |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | [Event logs](../../platforms/windows/event-logs.md#detect-log-clearing) | [SPL](../spl/windows-events.md#log-cleared-1102-104) |
| [T1564.008](https://attack.mitre.org/techniques/T1564/008/) | Email Hiding Rules | [Exchange inbox rules](../../platforms/microsoft-365/exchange.md#inbox-rules-on-a-mailbox) | — |
| [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software | [Installed software](../../platforms/windows/software.md#remote-access-tools-to-hunt-for) | — |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact (Ransomware) | [Ransomware Host Isolation](../../tasks/incident-response/ransomware-host-isolation.md) | [Automated Containment](../../tasks/incident-response/automated-containment.md) |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | [Service Principal Compromise](../../tasks/incident-response/compromised-service-principal.md) | [Entra ID Audit Logs](../../platforms/microsoft-365/entra.md) |
| [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | Modify Authentication Process: MFA | [Account Compromise](../../tasks/incident-response/account-compromise.md) | [SPL](../spl/mfa-deletion.md) |
| [T1584](https://attack.mitre.org/techniques/T1584/) | Compromise Infrastructure: Cloud Compute | [Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | [Azure Activity Logs](../../platforms/microsoft-365/entra.md) |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing (Spearphishing Link / Attachment) | [Phishing Email Triage](../../tasks/incident-response/phishing-email-triage.md) | [Exchange Message Trace](../../platforms/microsoft-365/exchange.md) |
| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | Steal or Forge Kerberos Tickets: Golden Ticket | [Kerberos Protocol](../../fundamentals/kerberos.md#2-attack-vectors) | [SPL](../spl/windows-events.md) · [KQL](../kql/logon-identity.md) |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Steal or Forge Kerberos Tickets: Kerberoasting | [Kerberos Protocol](../../fundamentals/kerberos.md#3-operational-inspection) | [SPL](../spl/windows-events.md) |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application (SQLi / SSRF) | [SQL Injection](../../fundamentals/web-apps/sql-injection.md) · [SSRF Defense](../../fundamentals/web-apps/ssrf-defense.md) | [HTTP Security Headers](../../fundamentals/web-apps/http-security-headers.md) |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | JavaScript (Cross-Site Scripting) | [XSS & CSP Defense](../../fundamentals/web-apps/xss-defense.md) | [Content Security Policy](../../fundamentals/web-apps/xss-defense.md#3-content-security-policy-csp) |

## Using ATT&CK in an entry

Add a technique link where the entry detects or investigates it, and the Sigma `tags` (`attack.t1059.001`) on rules. Keep this table in sync when you add detection content.

## Sources

- [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/)
