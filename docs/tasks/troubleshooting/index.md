---
title: Troubleshooting
type: index
---

# Troubleshooting

Diagnose broken services, connectivity and configuration — and recognize when a 'fault' is actually tampering.

## Interactive Triage Trees

Select an operational symptom to launch an interactive step-by-step diagnostic tree:

<div class="grid cards" markdown>

- :material-lan-disconnect:{ .lg .middle } **[Windows Network & Domain Connectivity](windows-connectivity.md)**
    
    Triage DNS resolution failures, gateway routing drops, TCP port 445/3389 drops, and Kerberos ticket errors.

- :material-server-network-off:{ .lg .middle } **[Linux Systemd Service Failures](linux-service-failure.md)**
    
    Triage immediate crashloops (`code=exited`), SELinux permission denials, port binding conflicts (`EADDRINUSE`), and missing environment variables.

- :material-speedometer-slow:{ .lg .middle } **[High CPU & Runaway Processes](high-cpu-troubleshooting.md)**
    
    Isolate runaway userland loops, kworker/kernel interrupt storms, cryptocurrency miners, and thread deadlocks.

- :material-file-lock-outline:{ .lg .middle } **[File or Port in Use](file-or-port-in-use.md)**
    
    Find which process holds a locked file, a busy mount or a port (`Address already in use`), identify it, then stop it safely.

- :material-harddisk-remove:{ .lg .middle } **[Emergency Disk Exhaustion & Inodes](disk-space-emergency.md)**
    
    Diagnose 100% capacity block exhaustion, inode exhaustion (`df -i`), unlinked open file descriptors (`lsof +L1`), and VSS shadow bloat.

- :material-certificate-outline:{ .lg .middle } **[TLS Handshake & Certificate Errors](certificate-handshake-failure.md)**
    
    Resolve incomplete intermediate CA chains, Subject Alternative Name (SAN) mismatches, protocol deprecation, and clock skew.

- :material-ssh:{ .lg .middle } **[SSH Connection Timeouts & Freezes](ssh-connection-timeout-troubleshooting.md)**
    
    Triage idle session disconnects, systemd sleep/suspend drops, network adapter power savings, and TCP keepalives.

- :material-vpn:{ .lg .middle } **[VPN & Remote Access Tunnels](vpn-connectivity-troubleshooting.md)**
    
    Triage GlobalProtect / WireGuard connection drops, AD CS machine cert auto-enrollment, MTU packet drops, and split-tunnel routing.

- :material-account-lock:{ .lg .middle } **[Active Directory Account Lockouts](account-lockout-troubleshooting.md)**
    
    Triage Event 4740 on PDC emulator, isolate Caller Computer, purge Credential Manager and stale mapped drive loops, and audit BadPwdCount.

</div>

## Workflows

<!-- cc:index tasks="Troubleshooting" type="workflow" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Active Directory Account Lockout & Bad Password Troubleshooting](account-lockout-troubleshooting.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD, Windows CLI | Troubleshooting, Administration |
| [Administration — BitLocker Key Retrieval & Status Audit](../administration/bitlocker-recovery.md) | Workflow | Windows, Active Directory | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Disk Space Capacity Audit & Reporting](../administration/disk-space-audit.md) | Workflow | Windows Server, Windows | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Group Policy Force Refresh & Diagnostic Audit](../administration/group-policy-update.md) | Workflow | Windows, Active Directory | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Remote Service Restart & Dependency Validation](../administration/remote-service-restart.md) | Workflow | Windows Server, Windows | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Safe Temporary File Purging](../administration/temp-file-cleanup.md) | Workflow | Windows Server, Windows | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — WireGuard Secure VPN Gateway & Client Deployment](../administration/wireguard-vpn-deployment.md) | Workflow | Linux, Windows | Bash, PowerShell | Administration, Hardening, Troubleshooting |
| [DNS Client Resolution and Troubleshooting](../administration/dns-resolution-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Failed Authentication Investigation](../investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Host Performance and System Resource Auditing](../administration/performance-resource-auditing.md) | Workflow | Windows, Linux | PowerShell, Bash, Python | Administration, Troubleshooting |
| [Linux Service Failure Troubleshooting](linux-service-failure.md) | Workflow | Linux | Bash | Troubleshooting, Administration |
| [Network Services Management](../administration/network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [SSH Connection Timeouts, Session Freezes & Host Sleep Drops](ssh-connection-timeout-troubleshooting.md) | Workflow | Linux, Windows | Bash, PowerShell | Troubleshooting, Administration |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [VPN & Remote Access Tunnel Troubleshooting](vpn-connectivity-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, Bash, Windows CLI | Troubleshooting |
| [Windows Connectivity Troubleshooting](windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |

<!-- /cc:index -->

## Reference entries

<!-- cc:index tasks="Troubleshooting" type="entry|tool|reference" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Amazon CloudWatch, Logs Insights & Athena](../../platforms/aws/monitoring-logs.md) | Entry | AWS | Bash, Python | Investigation, Troubleshooting, Detection Engineering, Administration |
| [AWS Networking (VPC, Security Groups, Flow Logs)](../../platforms/aws/networking.md) | Entry | AWS | Bash | Administration, Troubleshooting, Investigation, Hardening |
| [AWS Troubleshooting](../../platforms/aws/troubleshooting.md) | Entry | AWS | Bash | Troubleshooting, Administration |
| [Azure Monitor & Log Analytics Queries](../../platforms/azure/monitoring-logs.md) | Entry | Azure | Bash, PowerShell, KQL | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Azure Networking (VNets, NSGs, Flow Logs, Firewall)](../../platforms/azure/networking.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Troubleshooting, Investigation, Hardening |
| [Azure Troubleshooting](../../platforms/azure/troubleshooting.md) | Entry | Azure | Bash, PowerShell | Troubleshooting, Administration |
| [Bash Error Handling, Signals & Trap Handlers](../../languages/bash/error-handling-traps.md) | Entry | Linux | Bash | Automation, Troubleshooting |
| [Bash Pure Networking & /dev/tcp Socket Mechanics](../../languages/bash/networking-sockets.md) | Entry | Linux | Bash | Troubleshooting, Investigation |
| [CMD Error Handling & Exit Codes](../../languages/windows-cli/error-handling.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Automation, Troubleshooting, Administration |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Cross-platform data handling: Windows ↔ Linux, secrets, encodings and transport](../../fundamentals/systems/cross-platform-data-handling.md) | Entry | Windows, Linux, Proxmox | Python, PowerShell, Bash | Administration, Automation, Troubleshooting, Hardening |
| [Environment Variables and PATH](../administration/environment-variables-and-path.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Hardening |
| [File or Port in Use — Find and Stop the Holder](file-or-port-in-use.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Troubleshooting, Administration |
| [Fundamentals — DHCP Protocol Mechanics & IP Allocation](../../fundamentals/networking/dhcp.md) | Entry | Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Fundamentals — HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) | Entry | Linux, Windows | HTTP, PowerShell, Bash | Hardening, Assurance, Troubleshooting |
| [Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers](../../fundamentals/networking/http-https.md) | Entry | Linux, Windows Server | Bash, PowerShell | Investigation, Troubleshooting |
| [Fundamentals — Rate Limiting & Exponential Backoff](../../fundamentals/apis/rate-limiting-backoff.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — REST Architecture & HTTP Semantics](../../fundamentals/apis/rest-architecture.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — VPN Protocols (IPsec vs SSL/TLS)](../../fundamentals/networking/vpn.md) | Entry | Windows, Linux | PowerShell, Bash | Troubleshooting, Hardening |
| [Google Cloud Logging & BigQuery Log Queries](../../platforms/gcp/monitoring-logs.md) | Entry | GCP | Bash | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Google Cloud Troubleshooting](../../platforms/gcp/troubleshooting.md) | Entry | GCP | Bash | Troubleshooting, Administration |
| [Intune](../../platforms/microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [Linux Distributions, Package Systems & Release Baselines](../../platforms/linux/distros.md) | Entry | Linux | Bash | Administration, Troubleshooting |
| [Linux Filesystem](../../platforms/linux/filesystem.md) | Entry | Linux | Bash | Incident Response, Investigation, Forensics, Troubleshooting |
| [Linux Kernel Tuning & sysctl Runtime Optimization](../../platforms/linux/kernel-tuning.md) | Entry | Linux | Bash | Hardening, Troubleshooting |
| [Linux Logs](../../platforms/linux/logs.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Mandatory Access Control — SELinux & AppArmor](../../platforms/linux/selinux-apparmor.md) | Entry | Linux | Bash | Hardening, Troubleshooting |
| [Linux Networking and DNS](../../platforms/linux/networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Processes](../../platforms/linux/processes.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Services with systemd](../../platforms/linux/systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux Storage, Partitioning & Logical Volume Management (LVM)](../../platforms/linux/storage-lvm.md) | Entry | Linux | Bash | Administration, Troubleshooting |
| [Linux System Information](../../platforms/linux/system-information.md) | Entry | Linux | Bash | Incident Response, Administration, Troubleshooting |
| [Linux Terminal Sessions — screen, tmux & Background Jobs](../../platforms/linux/terminal-sessions.md) | Entry | Linux | Bash | Administration, Troubleshooting, Investigation, Incident Response |
| [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md) | Entry | Linux | Bash | Troubleshooting, Administration |
| [Microsoft Defender Antivirus](../../platforms/windows/defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [Search and Follow Logs by Keyword](../administration/search-logs-by-keyword.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Splunk REST API — Search Jobs Management](../../apis/splunk/management-jobs.md) | Entry | Splunk | PowerShell, Bash, REST API | Administration, Automation, Troubleshooting |
| [System32 Native Executables Field Guide](../../languages/windows-cli/system32-toolkit.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Administration, Investigation, Troubleshooting, Incident Response |
| [Windows 10 and 11 Version Notes](../../platforms/windows/windows-10-11.md) | Entry | Windows | PowerShell | Administration, Troubleshooting |
| [Windows Firewall](../../platforms/windows/firewall.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Administration, Hardening, Incident Response, Troubleshooting |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Server Notes](../../platforms/windows/windows-server.md) | Entry | Windows Server | PowerShell, Windows CLI | Administration, Incident Response, Troubleshooting |
| [Windows Storage & Disk Management](../../platforms/windows/storage-disks.md) | Entry | Windows, Windows Server | PowerShell, CMD | Administration, Troubleshooting |
| [Windows System Information](../../platforms/windows/system-information.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Administration, Troubleshooting |
| [Windows Troubleshooting Commands](../../platforms/windows/troubleshooting.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting, Administration |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |

<!-- /cc:index -->
