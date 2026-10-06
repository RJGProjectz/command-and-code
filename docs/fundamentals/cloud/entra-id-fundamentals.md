---
title: Fundamentals — Microsoft Entra ID Architecture & Hybrid Identity
type: entry
platforms:
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - entra
  - identity
  - hybrid-identity
  - cloud
---

# Fundamentals — Microsoft Entra ID Architecture & Hybrid Identity

Microsoft Entra ID is a multi-tenant, cloud-based identity and access management service distinct from on-premises Active Directory Domain Services.

## 1. Architectural Distinctions: AD DS vs Entra ID

| Capability | Active Directory Domain Services (AD DS) | Microsoft Entra ID |
| :--- | :--- | :--- |
| **Protocols** | Kerberos, NTLM, LDAP, SMB, RPC | OpenID Connect, OAuth 2.0, SAML 2.0, Microsoft Graph REST |
| **Structure** | Hierarchical OUs, Forests, Domains | Flat directory structure (Users, Groups, App Registrations) |
| **Device Join** | Domain Join via Kerberos (LAN / VPN required) | Entra Joined / Hybrid Joined via internet token enrollment |
| **Policy** | Group Policy Objects (GPOs) | Microsoft Intune / Conditional Access |
