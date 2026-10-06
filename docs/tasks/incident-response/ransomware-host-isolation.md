---
title: Investigation Playbook — Ransomware Host Isolation
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - playbook
  - ransomware
  - isolation
  - containment
---

# Investigation Playbook — Ransomware Host Isolation

High-speed containment protocol when active ransomware encryption, shadow copy purging, or mass file renaming is detected.

---

## 1. Objective & Golden Rules

- **Golden Rule 1**: **ISOLATE FIRST, ASK QUESTIONS LATER.** A 60-second hesitation can mean hundreds of thousands of encrypted files across network shares.
- **Golden Rule 2**: **DO NOT REBOOT OR POWER OFF.** Volatile memory contains the malware encryption keys, injected process handles, and C2 IP addresses.
- **MITRE ATT&CK Mapping**: [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/).

---

## 2. Immediate Containment Matrix

### Windows (EDR / Firewall Isolation)

```powershell
# 1. EDR Isolation (SentinelOne / Defender)
# If EDR is available, trigger instant network quarantine via management console.

# 2. Emergency Local Fallback (Software Firewall Killswitch)
# Blocks all ingress and egress except remote management
New-NetFirewallRule -DisplayName "EMERGENCY_ISOLATION_BLOCK_ALL" -Direction Outbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "EMERGENCY_ISOLATION_BLOCK_IN" -Direction Inbound -Action Block -Profile Any
```

### Linux (iptables emergency drop)

```bash
# Drop all external traffic except SSH management session
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

---

## 3. Preserving Forensic Artifacts

```powershell
# 1. Dump volatile memory to external media or secondary partition
# 2. Virtualized environments: Trigger hypervisor snapshot immediately (ESXi / Hyper-V)
Get-VM -Name "FileServer01" | Checkpoint-VM -SnapshotName "Forensics_Ransomware_PreRemediation"
```
