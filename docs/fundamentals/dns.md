---
title: Fundamentals — DNS Protocol Mechanics & Security
type: entry
platforms:
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Investigation
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - dns
  - networking
  - protocols
  - fundamentals
---

# Fundamentals — DNS Protocol Mechanics & Security

Domain Name System (DNS) operates on UDP/TCP port 53 and resolves human-readable domain names to routable IP addresses.

## 1. Resolution Flow

```text
Client ──► Local Cache / Hosts ──► Recursive Resolver ──► Root Server (.)
                                        │
                                        ├──► TLD Server (.com)
                                        └──► Authoritative Nameserver (example.com)
```

## 2. Common Record Types

| Type | Purpose | Security Significance |
| :--- | :--- | :--- |
| **A / AAAA** | IPv4 / IPv6 host mapping | Fast-flux malicious C2 infrastructure |
| **PTR** | Reverse lookup (IP to name) | Kerberos SPN ticket validation |
| **TXT** | Arbitrary text payload | SPF records, domain ownership, DNS tunneling exfiltration |
| **SRV** | Service locator | Active Directory domain controller discovery (`_ldap._tcp.dc._msdcs`) |
| **MX** | Mail exchanger | Email delivery routing and spoofing defense |

---

## 3. Threat Vectors & Exploitation

- **DNS Tunneling / Exfiltration** ([T1071.004](https://attack.mitre.org/techniques/T1071/004/)): Encoded data passed in subdomains (e.g., `data.attacker.com`) through egress port 53.
- **DNS Cache Poisoning / Spoofing** ([T1557](https://attack.mitre.org/techniques/T1557/)): Injecting false DNS mapping to redirect users to credential harvesting portals.

---

## 4. Operational Diagnostics

```powershell
# Windows client DNS cache inspection
Get-DnsClientCache | Where-Object Data -ne "" | Select-Object Entry, Type, Data, TimeToLive
```

```bash
# Linux recursive lookup trace
dig +trace example.com
```
