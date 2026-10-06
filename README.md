# Command & Code

<p align="center">
  <strong>The Practical Security Operations & Systems Administration Field Manual</strong>
</p>

<p align="center">
  <a href="https://rjgprojectz.github.io/command-and-code/"><img src="https://img.shields.io/badge/Live_Site-GitHub_Pages-2563eb?style=for-the-badge&logo=githubpages&logoColor=white" alt="Live Site"></a>
  <a href="https://github.com/RJGProjectz/command-and-code/actions/workflows/deploy.yml"><img src="https://img.shields.io/badge/Build_%26_Deploy-Automated-10b981?style=for-the-badge&logo=githubactions&logoColor=white" alt="Build Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" alt="License"></a>
</p>

---

## 📖 Explore the Live Manual
🌐 **[rjgprojectz.github.io/command-and-code](https://rjgprojectz.github.io/command-and-code/)**

**Command & Code** is an engineering-grade, copy-ready knowledge base of commands, code, queries, configuration locations, investigation workflows, detections, and automation for security operations and systems administration.

Written for analysts, engineers, and administrators who need to go from *"how do I…?"* to an exact, copy-ready answer in seconds.

---

## ⚡ What's Inside

```text
Platform  ──┐
Language  ──┼──▶  One connected entry, discoverable three ways
Task      ──┘
```

### 1. 🖥️ Multi-Platform Coverage
* **Windows & Windows Server**: Processes, services, networking, event logs, registry persistence, firewall, scheduled tasks, and Defender.
* **Linux**: Processes, systemd, networking, logs, cron, SSH hardening, user permissions, and package management.
* **Microsoft 365 & Cloud Identity**: Defender XDR, Entra ID, Conditional Access, Intune, and Exchange Online.
* **Virtualization**: VMware vSphere & ESXi, Microsoft Hyper-V, and Proxmox VE.

### 2. 🔍 Detection & Hunting Languages
* **KQL**: Endpoint process, network, file, registry, and sign-in queries for Microsoft Defender XDR and Sentinel.
* **SPL**: Optimized Splunk queries for Windows Security Event logs, PowerShell auditing, and Network traffic.
* **S1QL**: Hunting queries for SentinelOne Deep Visibility.
* **Sigma & MITRE ATT&CK**: Universal detection rules and mapped behavioral tactics.

### 3. 🛠️ Sysadmin Workflows & Cheat Sheets
* **[Sysadmin Quick Reference](https://rjgprojectz.github.io/command-and-code/references/sysadmin-cheat-sheet/)**: Side-by-side Windows vs. Linux rapid lookup matrix.
* **[PowerShell Admin One-Liners](https://rjgprojectz.github.io/command-and-code/references/powershell-cheat-sheet/)**: Copy-ready one-liners for inventory, AD, WMI/CIM, events, and remoting.
* **[Linux Sysadmin Speed Dial](https://rjgprojectz.github.io/command-and-code/references/linux-cheat-sheet/)**: Essential commands for systemd, journalctl, disks, processes, and network sockets.
* **[User Lifecycle Management](https://rjgprojectz.github.io/command-and-code/tasks/administration/user-lifecycle-management/)**: Onboarding, group role elevation, emergency offboarding, and cloud session revocation.
* **[System Maintenance & Updates](https://rjgprojectz.github.io/command-and-code/tasks/administration/system-maintenance-updates/)**: Patch management, pending reboot audits, and safe reboot sequencing.
* **[Cross-Platform Equivalents](https://rjgprojectz.github.io/command-and-code/references/equivalents/)**: The same task across PowerShell, Bash, KQL, SPL, and S1QL.

---

## 🚀 Quick Navigation

| Section | Focus Area | Quick Link |
| :--- | :--- | :--- |
| **Platforms** | OS & Cloud Platforms | [Windows](https://rjgprojectz.github.io/command-and-code/platforms/windows/) · [Linux](https://rjgprojectz.github.io/command-and-code/platforms/linux/) · [M365](https://rjgprojectz.github.io/command-and-code/platforms/microsoft-365/) · [Virtualization](https://rjgprojectz.github.io/command-and-code/platforms/virtualization/) |
| **Languages** | Code & Command Reference | [PowerShell](https://rjgprojectz.github.io/command-and-code/languages/powershell/) · [Bash](https://rjgprojectz.github.io/command-and-code/languages/bash/) · [Python](https://rjgprojectz.github.io/command-and-code/languages/python/) · [Windows CLI](https://rjgprojectz.github.io/command-and-code/languages/windows-cli/) |
| **Detection** | SIEM & EDR Queries | [KQL](https://rjgprojectz.github.io/command-and-code/detection/kql/) · [SPL](https://rjgprojectz.github.io/command-and-code/detection/spl/) · [S1QL](https://rjgprojectz.github.io/command-and-code/detection/s1ql/) · [ATT&CK](https://rjgprojectz.github.io/command-and-code/detection/mitre-attack/) |
| **Tasks** | Operational Procedures | [Incident Response](https://rjgprojectz.github.io/command-and-code/tasks/incident-response/) · [Administration](https://rjgprojectz.github.io/command-and-code/tasks/administration/) · [Hunting](https://rjgprojectz.github.io/command-and-code/tasks/threat-hunting/) |
| **References** | Lookups & Cheat Sheets | [Sysadmin Cheat Sheet](https://rjgprojectz.github.io/command-and-code/references/sysadmin-cheat-sheet/) · [Equivalents](https://rjgprojectz.github.io/command-and-code/references/equivalents/) · [Event IDs](https://rjgprojectz.github.io/command-and-code/references/windows-event-ids/) |

---

## 🔒 Security & Verification Standards

* **Honest Verification**: Every page clearly indicates whether it has been verified against vendor documentation (`verified: true`) or requires environment-specific testing.
* **Identifier Scrubbing**: Fully sanitized against corporate data leaks, internal hostnames, and private IPs via automated repository scanners.
* **Safe by Default**: State-changing commands and scripts emphasize `-WhatIf` / `--whatif` validation prior to execution.

---

## 🛠️ Development & Contributions

* For repository maintainers and local environment setup, see the **[Internal Maintenance Guide](DEVELOPMENT.md)**.
* For guidelines on contributing new entries or workflows, see **[CONTRIBUTING.md](CONTRIBUTING.md)**.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
