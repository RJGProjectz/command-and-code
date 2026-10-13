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
last_verified: 2026-10-12
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
| **Admin model** | Domain Admins, Enterprise Admins | Directory roles (Global Administrator, Privileged Role Administrator, …), ideally activated just-in-time through PIM |
| **What an attacker steals** | Password hashes, Kerberos tickets | Tokens (refresh tokens, Primary Refresh Token), app secrets and certificates |

## 2. Hybrid identity

Most organisations run both: users live in AD DS and are synchronised to Entra ID.

| Component / method | What it does | Security note |
| --- | --- | --- |
| **Entra Connect Sync** / **Cloud Sync** | Copies users, groups and (optionally) password hashes to Entra ID | The Connect server is **Tier 0**: whoever controls it can control cloud identities. Protect it like a domain controller |
| **Password hash sync (PHS)** | A hash of the AD password hash is synced; sign-in happens in the cloud | Recommended default; also enables leaked-credential detection |
| **Pass-through authentication (PTA)** | Cloud sign-ins are checked by agents against on-prem AD | Agents become Tier 0; on-prem outage blocks cloud sign-in |
| **Federation (AD FS)** | Sign-in is redirected to on-prem AD FS | Token-signing certificate theft = "Golden SAML"; migrate to PHS where possible |

## 3. Core security controls

- **MFA for everyone**, phishing-resistant (FIDO2 keys, Windows Hello, passkeys) for administrators.
- **Conditional Access**: require compliant or hybrid-joined devices for admin portals; block legacy authentication; block or restrict device-code flow.
- **Privileged Identity Management (PIM)**: no permanent Global Administrators beyond two break-glass accounts.
- **App consent**: stop users from consenting to third-party apps that request broad permissions; review existing grants.
- **Sign-in and audit logs** exported to your SIEM: the defaults keep them only 7–30 days, depending on licence.

## 4. Inspect

```powershell
# Device join state on a Windows machine (AzureAdJoined, DomainJoined, PRT present)
dsregcmd /status

# Members of every active directory role (Microsoft Graph PowerShell)
Connect-MgGraph -Scopes 'RoleManagement.Read.Directory'
Get-MgDirectoryRole | ForEach-Object {
    $role = $_
    Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id |
        Select-Object @{ n = 'Role'; e = { $role.DisplayName } }, Id, @{ n = 'Name'; e = { $_.AdditionalProperties['displayName'] } }
}
```

`Get-MgDirectoryRole` lists only roles that are in use (activated in the tenant). Roles assigned as *eligible* through PIM appear only after activation; list eligibility with the PIM role-eligibility cmdlets or in the portal.

## Related

- [Microsoft 365 / Entra platform](../../platforms/microsoft-365/entra.md)
- [Cloud identity persistence hunting](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md)
- [Account compromise](../../tasks/incident-response/account-compromise.md)

## Sources

- [Microsoft Learn — What is Microsoft Entra ID?](https://learn.microsoft.com/entra/fundamentals/whatis)
- [Microsoft Learn — Choose the right authentication method for hybrid identity](https://learn.microsoft.com/entra/identity/hybrid/connect/choose-ad-authn)
- [Microsoft Learn — Securing privileged access (enterprise access model)](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model)
- [Microsoft Learn — Get-MgDirectoryRole](https://learn.microsoft.com/powershell/module/microsoft.graph.identity.directorymanagement/get-mgdirectoryrole)
