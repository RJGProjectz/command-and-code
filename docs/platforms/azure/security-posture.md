---
title: Microsoft Defender for Cloud (Posture & Alerts)
platforms: [Azure, Microsoft Defender]
languages: [Bash, PowerShell, KQL]
tasks: [Assurance, Hardening, Investigation, Incident Response]
category: Posture
tags: [azure, defender for cloud, secure score, recommendations, security alerts, cspm, regulatory compliance]
aliases: [azure secure score, defender for cloud recommendations, defender for cloud alerts query, azure cspm, which defender plans enabled, azure security center]
difficulty: intermediate
verified: false
---

# Microsoft Defender for Cloud (Posture & Alerts)

Defender for Cloud (formerly Azure Security Center) does two jobs:

- **Posture (CSPM)**: recommendations and a **secure score** for misconfigurations. The free tier covers this; Defender CSPM adds attack-path analysis.
- **Workload protection (CWP)**: paid **Defender plans** per resource type (Servers, Storage, Key Vault, Containers, SQL, App Service, Resource Manager, ...) that raise **security alerts**.

Alerts also flow into the [Defender XDR portal](../microsoft-365/defender.md) and Microsoft Sentinel.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**. Enabling a Defender plan has a cost.

## 1. Which plans are on?

```bash
az security pricing list --query "value[].{plan:name, tier:pricingTier, subPlan:subPlan}" -o table
```

```powershell
Get-AzSecurityPricing | Select-Object Name, PricingTier, SubPlan
```

Turn on a plan (**change**): `az security pricing create -n VirtualMachines --tier Standard --subplan P2`

| Plan name | Covers | Gap if Free |
| :--- | :--- | :--- |
| `VirtualMachines` | Defender for Servers (MDE, vulnerability assessment, FIM) | No EDR onboarding or file-integrity monitoring |
| `StorageAccounts` | Malware scanning and anomalous access | No alert on mass download or malicious upload |
| `KeyVaults` | Unusual secret access | Bulk secret reads go unnoticed |
| `Arm` | Suspicious control-plane operations | No alert on toolkit use (MicroBurst, PowerZure) |
| `Containers` | AKS runtime and image scanning | No container-level threat detection |

## 2. Secure score and recommendations

```bash
az security secure-scores list --query "[].{name:displayName, current:score.current, max:score.max}" -o table
az security assessment list --query "[?status.code=='Unhealthy'].{rec:displayName, resource:resourceDetails.Id}" -o table
```

Across subscriptions with Resource Graph:

```kusto
securityresources
| where type == "microsoft.security/assessments"
| extend status = tostring(properties.status.code), severity = tostring(properties.metadata.severity),
         rec = tostring(properties.displayName), resource = tostring(properties.resourceDetails.Id)
| where status == "Unhealthy" and severity == "High"
| summarize Resources = count() by rec
| order by Resources desc
```

## 3. Security alerts

```bash
az security alert list --query "[].{time:timeGeneratedUtc, sev:severity, alert:alertDisplayName, status:status, resource:compromisedEntity}" -o table
az security alert show --location <region> -n <alert-name>
az security alert update --location <region> -n <alert-name> --status dismiss    # change
```

```kusto
// In a workspace with the Defender for Cloud connector / continuous export
SecurityAlert
| where TimeGenerated > ago(7d) and ProductName == "Azure Security Center"
| summarize Count = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by AlertName, AlertSeverity, CompromisedEntity
| order by Last desc
```

```kusto
// Pull IPs, accounts and hosts out of an alert for pivoting
SecurityAlert
| where SystemAlertId == "<alert-id>"
| mv-expand e = parse_json(Entities)
| project Type = tostring(e.Type), Address = tostring(e.Address), Name = tostring(e.Name), HostName = tostring(e.HostName)
```

## 4. Continuous export (change)

Recommendations and alerts are only kept in the portal. Export them to Log Analytics or Event Hubs so they are retained and can feed a SIEM. Configure it in **Environment settings → Continuous export**, or deploy it with the built-in policy *"Deploy export to Log Analytics workspace for Microsoft Defender for Cloud data"*.

## 5. Regulatory compliance

Defender for Cloud maps recommendations to standards (Microsoft cloud security benchmark by default; CIS, NIST SP 800-53, PCI DSS, ISO 27001 can be added).

```bash
az security regulatory-compliance-standards list --query "[].{std:name, state:state, passed:passedControls, failed:failedControls}" -o table
```

See [CIS benchmarks](../../fundamentals/grc/cis-benchmarks.md) and the [Azure security baseline](../../tasks/hardening/cloud-azure-security-baseline.md).

## 6. Triage an alert

1. Read the alert's **entities** (section 3) and **MITRE tactics**.
2. Pull the identity's control-plane activity from [Audit logging](audit-logging.md#3-investigation-queries-azureactivity).
3. For a VM alert, open the device in Defender XDR, or snapshot and isolate ([Incident response](incident-response.md)).
4. Record the outcome. Dismissing the alert without a note loses the decision.

## Related

- [Microsoft 365 → Defender XDR](../microsoft-365/defender.md)
- [Policy & governance](policy-governance.md)
- [Assurance tasks](../../tasks/assurance/index.md)

## Sources

- [Defender for Cloud overview](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction)
- [Secure score](https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls)
- [Continuous export](https://learn.microsoft.com/azure/defender-for-cloud/continuous-export)
