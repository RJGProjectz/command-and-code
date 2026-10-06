---
title: Splunk Detection — Suspicious MFA Authentication Method Deletion
type: entry
platforms:
  - Entra ID
  - Microsoft 365
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - mfa
  - entra-id
  - identity
  - persistence
---

# Splunk Detection — Suspicious MFA Authentication Method Deletion

Detects the deletion of multi-factor authentication (MFA) registration factors (FIDO2, Authenticator app, phone method) from user accounts in Microsoft Entra ID.

## Detection Logic

- **Log Source**: Azure AD Audit Logs (`sourcetype="azure:audit"`)
- **ATT&CK Technique**: [T1556.006 - Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)

```spl
index=azure sourcetype="azure:audit"
  (operationName="Delete user*" OR operationName="*method*" OR operationName="Delete windows hello for business")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by user, operationName, src_ip, result
| where count > 0
```

## Attack Scenario

Adversaries possessing compromised session tokens or secondary credentials remove existing MFA factors before registering their own device (MFA Swap) to secure persistence across password resets.

## Triage & Investigation Steps

1. Verify whether the IP initiating the deletion matches the employee's known VPN or ISP location.
2. Check if a new authentication method registration immediately followed the deletion:
   ```spl
   index=azure sourcetype="azure:audit" operationName="User registered security info" user="<TARGET_USER>"
   ```
3. If unauthorized, immediately revoke all active refresh tokens:
   `Revoke-MgUserSignInSession -UserId <UserObjectId>`
