---
title: Sigma Rules for Cloud Identity and Entra ID Attacks
type: entry
platforms:
  - Entra ID
  - Microsoft 365
  - Azure
languages:
  - Sigma
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-07
difficulty: intermediate
tags:
  - sigma
  - entra-id
  - cloud
  - service-principal
  - oauth
  - identity
---

# Sigma Rules for Cloud Identity and Entra ID Attacks

Sigma provides a vendor-agnostic specification that translates seamlessly into KQL, SPL, and SentinelOne queries for cloud identity attack detection.

---

## 1. Rule: Credential Added to Service Principal

Detects an adversary adding a new secret key or certificate to an existing application to maintain persistent tenant access ([T1098.001](https://attack.mitre.org/techniques/T1098/001/)).

```yaml
title: New Credential Added to Existing Service Principal
id: 5b6c7d8e-90f1-4a2b-8c3d-e4f5a6b7c8d9
status: production
description: Detects when a new password credential or key credential is added to an existing Azure AD / Entra ID service principal.
references:
  - https://attack.mitre.org/techniques/T1098/001/
author: Command & Code Detection Engineering
date: 2026-10-07
tags:
  - attack.persistence
  - attack.t1098.001
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    OperationName:
      - 'Add service principal credentials'
      - 'Update service principal credentials'
      - 'Add service principal'
    Result: 'success'
  condition: selection
falsepositives:
  - Legitimate DevOps CI/CD credential rotation by automation accounts.
level: high
```

---

## 2. Rule: Illicit High-Risk Application Consent Granted

Detects when an application is granted high-impact permissions (such as reading all user mail or modifying directory objects) via user or administrator consent ([T1528](https://attack.mitre.org/techniques/T1528/)).

```yaml
title: High-Privilege OAuth Application Consent Granted
id: 9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4
status: production
description: Detects granting of critical MS Graph permissions (Mail.ReadWrite, Directory.AccessAsUser.All) to enterprise applications.
references:
  - https://attack.mitre.org/techniques/T1528/
author: Command & Code Detection Engineering
date: 2026-10-07
tags:
  - attack.credential_access
  - attack.t1528
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    OperationName:
      - 'Consent to application'
      - 'Add delegated permission grant'
      - 'Add app role assignment to service principal'
  high_priv_scope:
    TargetResources.ModifiedProperties.NewValue|contains:
      - 'Mail.Read'
      - 'Mail.ReadWrite'
      - 'MailboxSettings.ReadWrite'
      - 'Directory.ReadWrite.All'
      - 'RoleManagement.ReadWrite.Directory'
  condition: selection and high_priv_scope
falsepositives:
  - Legitimate enterprise SaaS application deployments authorized by Global Administrators.
level: high
```

---

## 3. Rule: Cross-Tenant Federation Trust Modified

Detects tampering with domain authentication settings (Golden SAML attack vector) ([T1484.002](https://attack.mitre.org/techniques/T1484/002/)).

```yaml
title: Entra ID Domain Federation Trust Modified
id: 1f2e3d4c-5b6a-7890-bcde-f1a2b3c4d5e6
status: production
description: Detects modifications to domain authentication properties, including changes to signing certificates or federated domain metadata.
references:
  - https://attack.mitre.org/techniques/T1484/002/
author: Command & Code Detection Engineering
date: 2026-10-07
tags:
  - attack.defense_evasion
  - attack.t1484.002
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    OperationName:
      - 'Set domain authentication'
      - 'Set federation settings on domain'
      - 'Verify domain'
  condition: selection
falsepositives:
  - Scheduled federation certificate renewals conducted by identity engineering teams.
level: critical
```
