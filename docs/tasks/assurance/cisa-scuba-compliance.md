---
title: CISA SCuBA Microsoft 365 and Azure Baseline Compliance
type: workflow
platforms:
  - Microsoft 365
  - Azure
  - Entra ID
languages:
  - PowerShell
tasks:
  - Assurance
  - Compliance
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - cisa
  - scuba
  - scubagear
  - m365
  - entra-id
  - cloud-hardening
  - compliance
---

# CISA SCuBA Microsoft 365 and Azure Baseline Compliance

Auditing and verifying tenant configurations against the **Cybersecurity and Infrastructure Security Agency (CISA) Secure Cloud Business Applications (SCuBA)** baselines using the official **ScubaGear** PowerShell assessment engine.

---

## 1. CISA SCuBA Control Mapping

The CISA SCuBA project establishes mandatory baseline security policies for federal agencies and enterprise cloud tenants:

| CISA Policy ID | Component | Baseline Security Requirement | Command & Code Operational Link |
|:---|:---|:---|:---|
| **`MS.AAD.1.1v1`** | Entra ID | Phishing-resistant MFA enforced for all administrative roles | [Entra Baseline](../hardening/cloud-azure-security-baseline.md#5-entra-id-conditional-access-baseline-powershell) |
| **`MS.AAD.3.1v1`** | Entra ID | Legacy authentication protocols (POP3, IMAP, Basic Auth) blocked | [Conditional Access](../../platforms/microsoft-365/conditional-access.md) |
| **`MS.AAD.5.1v1`** | Entra ID | External guest invitations restricted to designated administrative roles | [Azure Guest Access Audit](azure-guest-access-audit.md) |
| **`MS.EXO.1.1v1`** | Exchange Online | Auto-forwarding of emails to external recipient domains disabled | [User Lifecycle](../administration/user-lifecycle-management.md) |
| **`MS.EXO.2.1v1`** | Exchange Online | Inbound DMARC, DKIM, and SPF validation enforced | [SMTP Fundamentals](../../fundamentals/networking/smtp.md) |
| **`MS.DEFENDER.1.1v1`** | Defender for Office | Safe Links and Safe Attachments policies active for all users | [Microsoft Defender](../../platforms/microsoft-365/defender.md) |

---

## 2. Running ScubaGear Assessment

### Prerequisites & Module Installation
Execute in an elevated PowerShell 7 session:

```powershell
# Install official CISA ScubaGear module from PowerShell Gallery
Install-Module -Name ScubaGear -Scope CurrentUser -Repository PSGallery -Force

# Verify installed ScubaGear version
Get-InstalledModule -Name ScubaGear
```

### Tenant Audit Execution
Execute tenant-wide baseline evaluation across Entra ID, Defender, and Exchange:

```powershell
# Run SCuBA audit against active Microsoft 365 services
Import-Module ScubaGear
Invoke-SCuBA -ProductNames aad, defender, exo -OutPath "C:\\Audits\\CISA-SCuBA"
```

The assessment generates:
- `ScubaResults.html`: Interactive visual compliance dashboard with pass/fail badges.
- `ScubaResults.json`: Machine-readable results for ingestion into SIEM or compliance tracking.

---

## 3. High-Priority Remediation Scripts

### Block Legacy Authentication (`MS.AAD.3.1v1`)
Enforce Conditional Access policy blocking basic authentication clients:

```powershell
# Check for active sign-ins using legacy protocols
Get-MgAuditLogSignIn -Filter "clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'" -Top 20 |
    Select-Object UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress

# Confirm Conditional Access policy blocking legacy auth exists
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -match "Block Legacy Auth" } | Select-Object Id, DisplayName, State
```

### Restrict Guest User Permissions (`MS.AAD.5.1v1`)
Enforce restricted guest access settings so guests cannot enumerate directory members:

```powershell
# Connect to Microsoft Graph with Policy administration scope
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Set authorization policy to restrict guest permissions to their own profile
$Params = @{
    GuestUserRoleId = "2af84b1e-32c8-42b7-82bc-06b824e1e864" # Restricted Guest User
}
Update-MgPolicyAuthorizationPolicy -BodyParameter $Params

# Verify guest restriction policy state
Get-MgPolicyAuthorizationPolicy | Select-Object Id, GuestUserRoleId
```

### Disable Automatic External Mail Forwarding (`MS.EXO.1.1v1`)

```powershell
# Connect to Exchange Online PowerShell
Connect-ExchangeOnline

# Inspect remote domain auto-forwarding rule (Default policy)
Get-RemoteDomain "Default" | Select-Object Name, AutoForwardEnabled

# Disable auto-forwarding to prevent exfiltration via mail forwarding
Set-RemoteDomain -Identity "Default" -AutoForwardEnabled $false
```
