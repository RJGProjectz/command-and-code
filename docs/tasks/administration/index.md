---
title: Administration
type: index
---

# Administration

Day-to-day systems and security administration: accounts, services, configuration, patching, hypervisors, and platform management.

## Core Administration Workflows

| Workflow | Scope | Platforms | Languages |
| :--- | :--- | :--- | :--- |
| **[User Lifecycle Management](user-lifecycle-management.md)** | Onboarding, role elevation, offboarding & session revocation | Windows Server, Entra ID, Microsoft 365 | PowerShell |
| **[System Maintenance & Updates](system-maintenance-updates.md)** | Patch management, pending reboot audit & safe rebooting | Windows Server, Linux | PowerShell, Bash |
| **[Network Services Management](network-services-management.md)** | DNS records, DHCP reservations & host firewall rules | Windows Server, Linux | PowerShell, Bash |
| **[Backup & Recovery Operations](backup-and-recovery.md)** | VM snapshot cleanup, hypervisor backup audit & LVM | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash |
| **[Certificate & PKI Management](certificate-and-pki-management.md)** | SSL/TLS expiration audit, IIS PFX import & Certbot | Windows Server, Linux | PowerShell, Bash |

## All Administration Entries

<!-- cc:index tasks="Administration" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Backup and Recovery Operations](backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [Linux Service Failure Troubleshooting](../troubleshooting/linux-service-failure.md) | Workflow | Linux | Bash | Troubleshooting, Administration |
| [Network Services Management](network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Troubleshooting |
| [System Maintenance and Updates](system-maintenance-updates.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Automation |
| [User Lifecycle Management](user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Bash Scripting and Automation](../../languages/bash/automation.md) | Entry | Linux | Bash | Automation, Administration, Incident Response |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Entra ID](../../platforms/microsoft-365/entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](../../platforms/microsoft-365/exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Hyper-V](../../platforms/virtualization/hyper-v.md) | Entry | Hyper-V, Windows Server | PowerShell | Administration, Incident Response, Forensics |
| [Intune](../../platforms/microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Linux Installed Packages](../../platforms/linux/packages.md) | Entry | Linux | Bash | Investigation, Administration, Forensics |
| [Linux Networking and DNS](../../platforms/linux/networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Services with systemd](../../platforms/linux/systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux SSH](../../platforms/linux/ssh.md) | Entry | Linux | Bash | Incident Response, Investigation, Hardening, Administration |
| [Linux System Information](../../platforms/linux/system-information.md) | Entry | Linux | Bash | Incident Response, Administration, Troubleshooting |
| [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md) | Entry | Linux | Bash | Troubleshooting, Administration |
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Microsoft Defender Antivirus](../../platforms/windows/defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [Microsoft Defender XDR and Defender for Endpoint](../../platforms/microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [PowerShell Automation and Remoting](../../languages/powershell/automation.md) | Entry | Windows, Windows Server | PowerShell | Automation, Incident Response, Administration |
| [PowerShell Fundamentals and Pitfalls](../../languages/powershell/fundamentals.md) | Entry | Windows, Windows Server | PowerShell | Automation, Administration |
| [Proxmox VE](../../platforms/virtualization/proxmox.md) | Entry | Proxmox, Linux | Bash | Administration, Incident Response, Forensics |
| [VMware vSphere and ESXi](../../platforms/virtualization/vmware.md) | Entry | VMware | PowerShell, Bash | Administration, Incident Response, Forensics |
| [Windows 10 and 11 Version Notes](../../platforms/windows/windows-10-11.md) | Entry | Windows | PowerShell | Administration, Troubleshooting |
| [Windows Firewall](../../platforms/windows/firewall.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Administration, Hardening, Incident Response, Troubleshooting |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Server Notes](../../platforms/windows/windows-server.md) | Entry | Windows Server | PowerShell, Windows CLI | Administration, Incident Response, Troubleshooting |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows System Information](../../platforms/windows/system-information.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Administration, Troubleshooting |
| [Windows Troubleshooting Commands](../../platforms/windows/troubleshooting.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting, Administration |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [PowerShell Admin One-Liners Cheat Sheet](../../references/powershell-cheat-sheet.md) | Reference | Windows, Windows Server | PowerShell | Administration, Investigation, Automation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |

<!-- /cc:index -->
