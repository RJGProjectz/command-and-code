---
title: Fundamentals — LDAP Protocol, Directory Trees & LDAPS
type: entry
platforms:
  - Windows Server
  - Linux
  - Active Directory
languages:
  - PowerShell
  - Bash
tasks:
  - Administration
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - ldap
  - ldaps
  - active-directory
  - directory-services
---

# Fundamentals — LDAP Protocol, Directory Trees & LDAPS

Lightweight Directory Access Protocol (LDAP) runs over TCP 389 (plain/StartTLS) and TCP 636 (LDAPS), querying and modifying hierarchical directory databases.

## 1. Distinguished Names (DN) & Directory Structure

```text
CN=John Doe,OU=Engineering,OU=Corporate,DC=example,DC=com
 │          │              │            └─────────────── Domain Component
 │          └──────────────┴──────────────────────────── Organizational Units
 └────────────────────────────────────────────────────── Common Name
```

## 2. LDAP Search Filter Syntax

- Equality: `(sAMAccountName=jdoe)`
- Logical AND: `(&(objectClass=user)(objectCategory=person)(department=Finance))`
- Logical OR: `(|(memberOf=CN=Admins,...)(memberOf=CN=IT,...))`
- Negation: `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` *(Accounts that are NOT disabled)*

---

## 3. Security Concerns: Channel Binding & LDAPS Signing

Unsigned LDAP allows cleartext credential sniffing and NTLM relaying. Enforce **LDAP Channel Binding** and **LDAP Server Signing** to mandate TLS encryption for all directory operations.
