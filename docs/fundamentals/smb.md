---
title: Fundamentals — SMB Protocol & Network Share Security
type: entry
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
tasks:
  - Investigation
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - smb
  - fileshares
  - signing
  - fundamentals
---

# Fundamentals — SMB Protocol & Network Share Security

Server Message Block (SMB) provides shared access to files, printers, and named pipes over TCP port 445.

## 1. SMB Dialects & Security Evolution

- **SMBv1**: Obsolete, plain-text negotiation, vulnerable to EternalBlue ([MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)). **Must be disabled.**
- **SMBv2 (SMB 2.1)**: Introduced in Windows Vista / Server 2008, added compound requests and MTU scalability.
- **SMBv3 (SMB 3.1.1)**: Modern standard. Features end-to-end AES-128/256-GCM encryption, pre-authentication integrity, and required SMB signing.

---

## 2. SMB Signing & NTLM Relay Defense

Without SMB signing, an attacker in the network path can intercept authentication requests (e.g. via LLMNR/NBT-NS poisoning) and relay NTLM credentials to a target server to gain administrative execution.

```powershell
# Audit SMB Server configuration for signing and SMBv1 state
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData
```
