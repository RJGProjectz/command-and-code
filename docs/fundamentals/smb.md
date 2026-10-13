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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - smb
  - fileshares
  - signing
  - fundamentals
---

# Fundamentals — SMB Protocol & Network Share Security

Server Message Block (SMB) provides shared access to files, printers, and named pipes over TCP port 445.

SMB is also the transport for much of Windows remote administration (named pipes for service control, scheduled tasks, WMI fallback), which is why attackers use it for lateral movement with stolen credentials.

## 1. SMB Dialects & Security Evolution

- **SMBv1**: Obsolete (Windows 2000/XP era). No signing by default, no encryption, and the protocol behind EternalBlue / WannaCry ([MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)). **Must be disabled**; recent Windows versions no longer install it.
- **SMBv2 (SMB 2.0 / 2.1)**: Introduced in Windows Vista / Server 2008 and Windows 7 / 2008 R2. Fewer commands, compound requests, larger reads and writes.
- **SMBv3 (3.0 – 3.1.1)**: Windows 8 / Server 2012 onwards. AES-128/256 encryption (GCM/CCM), pre-authentication integrity (3.1.1) against downgrade attacks, and AES-based signing.

Default signing requirements: domain controllers require it from every client. Windows 11 24H2 Enterprise, Pro and Education require it both outbound and inbound; Windows Server 2025 requires it outbound only; 24H2 Home and older versions require it in neither direction. A connection is signed when **either** side requires it.

## 2. SMB Signing & NTLM Relay Defense

Without SMB signing, an attacker in the network path can intercept authentication requests (e.g. via LLMNR/NBT-NS poisoning) and relay NTLM credentials to a target server to gain administrative execution.

```powershell
# Audit SMB Server configuration for signing and SMBv1 state
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData

# Client side (EnableSecuritySignature is ignored for SMB2 and later; only Require* matters)
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature

# Live sessions: dialect, signing and encryption per connection
Get-SmbConnection | Select-Object ServerName, ShareName, Dialect, Signed, Encrypted
```

Defences that work together:

| Control | Stops |
| --- | --- |
| Require SMB signing (server and client) | NTLM relay to SMB |
| Disable LLMNR and NetBIOS-NS | The poisoning that captures credentials in the first place |
| Block TCP 445 between workstations | Workstation-to-workstation lateral movement |
| Block TCP 445 outbound to the internet | Leaking NTLM hashes to external servers |
| Disable SMBv1 | EternalBlue-class exploits |

## 3. Shares and permissions

Effective access is the **more restrictive** of the share permission and the NTFS permission.

```powershell
Get-SmbShare | Select-Object Name, Path, Description
Get-SmbShareAccess -Name <share>
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
```

`C$`, `ADMIN$` and `IPC$` are hidden administrative shares. Remote access to `ADMIN$` followed by a new service (event 7045) is the PsExec pattern.

## 4. Detect it

- Windows Security 5140 (share accessed) and 5145 (detailed file share, very noisy) after enabling *Audit File Share*.
- 4624 logon type 3 from a workstation to many other workstations in a short time.
- → [SMB Lateral Movement](../tasks/incident-response/smb-lateral-movement.md) · [SPL lateral movement over SMB](../detection/spl/lateral-movement-smb.md)

## Sources

- [Microsoft Learn — Overview of SMB signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview)
- [Microsoft Learn — Detect, enable and disable SMBv1, SMBv2 and SMBv3](https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Microsoft Learn — SMB security enhancements](https://learn.microsoft.com/windows-server/storage/file-server/smb-security)
