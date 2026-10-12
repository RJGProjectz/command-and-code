---
title: Authentication, MFA, SSO and Federation
type: concept
platforms: [Windows, Entra ID, Microsoft 365]
languages: [PowerShell, KQL]
tasks: [Investigation, Hardening, Incident Response]
category: Identity Concepts
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, authentication, mfa, sso, federation]
aliases: [authentication, Authentication Mechanisms, Authentication Protocols, Multi-Factor Authentication (MFA), Single Sign-On, Single Sign-On and Federation, Federation]
difficulty: basic
verified: false
---

# Authentication, MFA, SSO and Federation
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** authentication proves an identity with one or more factors, and single sign-on with federation lets one trusted sign-in unlock many applications.

## What it is

**Factors:** something you know (password, PIN), have (phone, FIDO2 key, smart card) or are (biometric). **MFA**
combines two different factor types. Not all MFA is equal:

| Method | Phishing-resistant? | Typical attack |
| :--- | :--- | :--- |
| SMS / voice code | no | SIM swap, real-time phishing relay |
| Authenticator push | no | MFA fatigue (push bombing), AiTM relay |
| Number matching / TOTP | no (but better) | AiTM relay |
| **FIDO2 / passkeys, Windows Hello, smart cards** | **yes** — bound to the real site's origin | device theft + PIN |

**Protocols:** NTLM and [Kerberos](../kerberos.md) inside Windows domains; LDAP binds; RADIUS for network access;
**SAML 2.0** and **OpenID Connect** ([OAuth 2.0](../identity/oauth2.md)) for web SSO.

**SSO** means one sign-in at an identity provider (Entra ID, Okta, AD FS) issues tokens that many applications accept.
**Federation** extends that trust across organisations or domains: the application trusts assertions signed by the
other side's IdP.

## How it works

1. User signs in to the IdP; policy ([Conditional Access](../../platforms/microsoft-365/conditional-access.md)) decides
   which factors are needed.
2. IdP issues a signed token (SAML assertion, ID/access token) or a Kerberos ticket.
3. Applications validate the signature and trust the claims — so **a stolen token or a stolen signing key bypasses
   passwords and MFA** (pass-the-cookie, Golden SAML).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1621](https://attack.mitre.org/techniques/T1621/) MFA Request Generation · [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie · [T1606.002](https://attack.mitre.org/techniques/T1606/002/) Forge SAML Tokens · [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| **What it leads to** | account takeover despite MFA, tenant-wide access from one IdP compromise |
| **Where defenders meet it** | MFA fatigue reports, impossible-travel alerts, sign-ins without MFA from legacy protocols |

## Do it

```powershell
# Which authentication methods does a user have registered? (Microsoft Graph PowerShell)
Get-MgUserAuthenticationMethod -UserId 'user@contoso.com' |
    Select-Object -Property Id, @{Name = 'Type'; Expression = { $_.AdditionalProperties['@odata.type'] } }
```

```kql
// Sign-ins that satisfied only single-factor auth, by app
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignIns = count() by AppDisplayName, ClientAppUsed
| order by SignIns desc
```

## See it

| Source | What you see |
| :--- | :--- |
| Entra `SigninLogs` | `AuthenticationRequirement`, `MfaDetail`, `ConditionalAccessStatus`; ResultType `500121` = MFA denied/failed |
| Security events 4624 / 4625 / 4776 | Windows logons, failures, NTLM validation |
| AD FS / IdP logs | token issuance per relying party |

## Detect it

- Investigate: [Failed authentication](../../tasks/investigation/failed-authentication.md) · [Account compromise](../../tasks/incident-response/account-compromise.md)
- Hunt: [KQL logon & identity](../../detection/kql/logon-identity.md)
- Harden: [Conditional Access](../../platforms/microsoft-365/conditional-access.md) · [Entra ID fundamentals](../cloud/entra-id-fundamentals.md)

## Related concepts

- [Identity and Access Management](identity-access-management.md) · [Access Control Models](access-control-models.md) · [Man-in-the-Middle Attacks](man-in-the-middle.md) · [Social Engineering](social-engineering.md)
