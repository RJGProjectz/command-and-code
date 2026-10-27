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

Written for analysts, engineers, and administrators who need to go from *"how do I…?"* to an exact, copy-ready answer in seconds — **482 pages** across four top-level tabs.

---

## 🗂️ Site Structure

| Tab | Focus |
| :--- | :--- |
| **Foundations** | Platforms, Shells, and Concepts — the building blocks |
| **Offensive** | Authorized red-team enumeration & assessment, 5-stage lifecycle |
| **Defensive** | Detection queries, hardening, assurance, investigation & IR playbooks |
| **Reference** | Cheat sheets, cookbooks, command index, coverage matrix |

---

## ⚡ What's Inside

### 🖥️ Platforms — 10 Environments Covered

| Platform | Coverage |
| :--- | :--- |
| **Windows 11 / Server 2022** | Processes, services, networking, event logs, registry persistence, firewall, scheduled tasks, Defender |
| **Linux** | systemd, networking, journalctl, cron/timers, SSH, users/permissions, package management, disk encryption |
| **Microsoft 365 & Entra ID** | Defender XDR, Conditional Access, Intune, Exchange Online, PIM |
| **Azure** | 15 pages — CLI auth, IAM/RBAC, compute, networking, storage, audit logging, security posture, IR |
| **AWS** | 15 pages — IAM, CloudTrail/Config, S3, GuardDuty, VPC, KMS, incident response |
| **GCP** | 15 pages — IAM, Cloud Audit Logs, SCC, VPC, KMS, VM metadata hardening |
| **GitHub** | 9 pages — PATs/SSH/GPG, branch protection, Actions security, OIDC, secret scanning, leaked-token response |
| **Virtualization** | VMware vSphere & ESXi, Microsoft Hyper-V, Proxmox VE |
| **Shells** | PowerShell, Bash, Python, Windows CLI — cross-platform equivalents table |

---

### 🔍 Detection & Hunting — 4 Query Languages + Sigma/ATT&CK

* **KQL** — Endpoint process/network/file/registry, identity sign-ins, cloud activity, web attacks (Microsoft Defender XDR & Sentinel)
* **SPL** — Windows Security events, PowerShell auditing, network/proxy traffic, lateral movement, brute force, web attacks (Splunk)
* **S1QL** — Deep Visibility hunting queries for SentinelOne
* **Sigma** — 13+ verified detection rules; CI-validated, doc-checked event IDs; mapped to **MITRE ATT&CK v20**
* **Detection Engineering** — Detection-as-code pipeline (version control, CI validation, staged deploy)

---

### 🔒 Offensive Tab — Authorized Red-Team Assessment

Five-stage red-team lifecycle; **enumeration/assessment-only** (no weaponized payloads; authorized-lab framing throughout):

| Stage | Workflow Pages |
| :--- | :--- |
| 1 · Reconnaissance | Web App Assessment, Web API Assessment, OSINT & Active Recon, Wi-Fi / Wireless Assessment, Network & Infra Enumeration, Passive Web OSINT |
| 2 · Initial Access | Password Attacks & Credential Cracking, Phishing & Social-Engineering Simulation |
| 3 · Foothold & C2 | Awareness + Detect-it / Harden-it only |
| 4 · Lateral Movement & Privesc | AD Attack Surface, Windows Host Escalation, Linux Host Escalation, Cloud Attack Surface, Container & Kubernetes Attack Surface, LLM Application Assessment |
| 5 · Actions on Objectives & Reporting | Awareness + Detect-it / Harden-it only |

Every offensive page links to its **Detect it** (query) and **Harden it** (control) counterparts in the Defensive tab.

---

### 🛠️ Defensive Tab — Hardening, Assurance & Response

**Hardening & Assurance**
* CIS Windows 11 Audit Tool — 486 L1/L2 checks (WS2022 catalogs included)
* CIS Windows Server Audit Tool — Member Server & DC profiles
* CIS Linux Audit Tool — Ubuntu 24.04 & RHEL 9 profiles
* CIS Block Monitor — AppLocker, WDAC, Defender ASR, SELinux/AppArmor denials
* Posture Audit (`Invoke-PostureAudit`) — one-command workstation/server/AD posture report, auto-detects role; 27-check AD domain posture module with STIG + CIS crosswalk
* Lab Retrieval Flow — zero-WinRM bundle + collect scripts (SMB/SCP/USB)
* Phase 15 Hardening — Linux & Windows least-privilege service accounts, LAPS deployment, JEA/sudo/polkit delegation, SSH certificate authority, LUKS2 encryption, file integrity monitoring (AIDE + Windows SACLs/Sysmon)

**Operate / Detect / Respond**
* Incident Response — account compromise, ransomware, cloud IR, credential rotation after compromise, eradication & recovery, post-incident lessons-learned (NIST SP 800-61 lifecycle)
* Forensics — memory triage, network/PCAP, disk forensics
* Threat Hunting — scheduled-task persistence, LOLBins, cloud identity hunting, DNS tunneling

---

### 📚 Concepts Layer — Theory to Tools

47 concept pages bridge theory to practical commands, organized into 7 groups:

> Operating Systems · Cryptography · Identity & Access · Network Attacks & Recon · Wireless · Cloud, AppSec & DevSecOps · Privacy, Law & GRC

Each concept page links directly to the task/platform pages where the concept is put into practice, with detection rules and hardening controls cross-referenced.

---

### 📋 Reference — Cheat Sheets & Cookbooks

| Reference | Contents |
| :--- | :--- |
| **[Sysadmin Quick Reference](https://rjgprojectz.github.io/command-and-code/references/sysadmin-cheat-sheet/)** | Side-by-side Windows vs. Linux rapid lookup matrix |
| **[PowerShell Admin One-Liners](https://rjgprojectz.github.io/command-and-code/references/powershell-cheat-sheet/)** | Inventory, AD, WMI/CIM, events, remoting |
| **[Linux Sysadmin Speed Dial](https://rjgprojectz.github.io/command-and-code/references/linux-cheat-sheet/)** | systemd, journalctl, disks, processes, sockets |
| **[Windows Triage Cheat Sheet](https://rjgprojectz.github.io/command-and-code/references/windows-triage-cheat-sheet/)** | Printable one-page IR rapid-triage card |
| **[Linux Triage Cheat Sheet](https://rjgprojectz.github.io/command-and-code/references/linux-triage-cheat-sheet/)** | Printable one-page Linux IR triage card |
| **[Cloud IR Cheat Sheet](https://rjgprojectz.github.io/command-and-code/references/cloud-ir-cheat-sheet/)** | Printable one-page cloud incident-response card |
| **[Command Index](https://rjgprojectz.github.io/command-and-code/references/command-index/)** | ~90 jobs cross-referenced across PowerShell/CMD/Bash |
| **[Identity & Directory Query Cookbook](https://rjgprojectz.github.io/command-and-code/references/identity-directory-query-cookbook/)** | On-prem AD + Entra ID/Graph recipes: user lookup, wildcard search, nested groups, privileged roles, SPNs, stale accounts |
| **[Cross-Platform Equivalents](https://rjgprojectz.github.io/command-and-code/references/equivalents/)** | Same task across PowerShell, Bash, KQL, SPL, S1QL |

---

## 🤖 AI-Powered `cc ask`

The site ships a local AI assistant powered by **Ollama (llama3.2)** — no cloud calls, no data leaving the machine:

```bash
python tools/cc.py ask "how do I isolate a compromised host?"
```

Returns a grounded answer with **cited source pages** from the knowledge base (hit@5 100%, MRR 0.94 on the internal eval set). Available in the terminal or via `cc ask` in the CLI.

---

## 🔒 Security & Verification Standards

* **Honest Verification** — Every page displays whether it has been verified against vendor documentation (`verified: true`) or requires environment-specific testing (`verified: false`).
* **MITRE ATT&CK v20** — All technique IDs kept current; CI blocks stale or revoked IDs.
* **Identifier Scrubbing** — Automated scanner rejects corporate hostnames, private IPs, and internal tokens before commit.
* **Safe by Default** — State-changing commands emphasize `-WhatIf` / dry-run validation prior to live execution.
* **CI Gates** — Every push runs: MkDocs strict build, PSScriptAnalyzer, ShellCheck, Pester contract suite (550+ tests), pytest (55+ tests), MITRE ID validator, and the `cc ask` retrieval eval.

---

## 🛠️ Development & Contributions

* Local environment setup and tooling: **[DEVELOPMENT.md](DEVELOPMENT.md)**
* Contributing new entries, workflows, or detections: **[CONTRIBUTING.md](CONTRIBUTING.md)**

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
