---
title: CMD (Windows CLI)
type: index
---

# CMD (Windows Command Prompt)

Windows Command Prompt knowledge lives in two places:

- **Language pages** (below) — command syntax, batch scripting standards, native text parsing with `findstr`, errorlevel trapping, and the System32 diagnostic toolkit.
- **Platform entries & tasks** tagged *CMD* or *Windows CLI* — operational workflows for incident response, system administration, and network troubleshooting.

Native `cmd.exe` tools are indispensable: they execute in restricted shells, WinPE recovery consoles, and EDR live-response environments where PowerShell execution policies or Constrained Language Mode block scripts.

!!! warning "Calling them from PowerShell"
    Always include `.exe` for tools whose names collide with PowerShell built-in aliases (e.g. `sc.exe`, not `sc`). Native tools signal failure through `$LASTEXITCODE` rather than PowerShell terminating exceptions.

## Language pages

- [Fundamentals & Syntax](fundamentals.md) — Command prompt mechanics, environment variables, delayed expansion (`!VAR!`), escaping, redirection, and pipes
- [Batch Defensive Scripting](batch-scripting.md) — Strict `.cmd` boilerplate, argument modifiers (`%~dp0`), `for` loops, subroutines, and dry-run simulation
- [Text Processing & findstr](text-processing.md) — Native stream filtering, `findstr` regex rules, CSV/delimited data parsing with `for /f`
- [Error Handling & Exit Codes](error-handling.md) — Trapping `%ERRORLEVEL%`, Robocopy bitmap exit codes, and conditional execution chains (`&&`, `||`)
- [System32 Native Executables](system32-toolkit.md) — Comprehensive reference for `tasklist`, `taskkill`, `sc.exe`, `netstat`, `netsh`, `reg.exe`, `wevtutil`, and `icacls`

## Everything tagged Windows CLI

<!-- cc:index languages="Windows CLI" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Registry Persistence Investigation](../../tasks/investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Windows Connectivity Troubleshooting](../../tasks/troubleshooting/windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |
| [Batch Defensive Scripting & Automation](batch-scripting.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Automation, Administration |
| [CMD Error Handling & Exit Codes](error-handling.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Automation, Troubleshooting, Administration |
| [CMD Fundamentals & Syntax](fundamentals.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Administration, Automation |
| [Fundamentals — Windows Process Architecture, Tokens & Handles](../../fundamentals/systems/windows-processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Forensics |
| [Intune](../../platforms/microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [Microsoft Defender Antivirus](../../platforms/windows/defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [System32 Native Executables Field Guide](system32-toolkit.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Administration, Investigation, Troubleshooting, Incident Response |
| [Text Processing & findstr](text-processing.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Investigation, Automation, Administration |
| [Windows Event Logs](../../platforms/windows/event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](../../platforms/windows/files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Firewall](../../platforms/windows/firewall.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Administration, Hardening, Incident Response, Troubleshooting |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Server Notes](../../platforms/windows/windows-server.md) | Entry | Windows Server | PowerShell, Windows CLI | Administration, Incident Response, Troubleshooting |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows System Information](../../platforms/windows/system-information.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Administration, Troubleshooting |
| [Windows Troubleshooting Commands](../../platforms/windows/troubleshooting.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting, Administration |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |

<!-- /cc:index -->
