---
title: Azure
type: index
---

# Azure

Microsoft Azure infrastructure: subscriptions, RBAC, VMs, networking, storage, Key Vault, AKS, Defender for Cloud and Azure Policy. Identity itself (users, sign-ins, Conditional Access) lives under [Microsoft 365 → Entra ID](../microsoft-365/entra.md).

!!! info "Tools"
    Use the **Azure CLI** (`az`) or the **Az PowerShell** module (`Az.Accounts`, `Az.Resources`, ...). Run queries over logs in **Log Analytics (KQL)**. AzureRM is retired; do not build new automation on it.

## Topics

Every cloud uses the same topic set, so the Azure, AWS and GCP pages line up side by side.

| Topic | Covers | Page |
| --- | --- | --- |
| CLI, SDK & authentication | az / Az PowerShell login, service principals, managed identity | planned (WP-35) |
| Resource hierarchy & inventory | Tenant, management groups, subscriptions, resource groups; Resource Graph | planned (WP-35) |
| Identity & access | Azure RBAC, PIM, managed identities | planned (WP-35) |
| Compute | Virtual machines, Run Command, extensions | planned (WP-35) |
| Networking | VNets, NSGs, flow logs, Azure Firewall | planned (WP-35) |
| Storage & data exposure | Storage accounts, SAS tokens, public blobs | planned (WP-35) |
| Audit logging | Activity Log, Entra sign-in/audit logs, diagnostic settings | planned (WP-35) |
| Monitoring & log queries | Azure Monitor, Log Analytics, KQL | planned (WP-35) |
| Keys & secrets | Key Vault keys, secrets, access policies vs RBAC | planned (WP-35) |
| Kubernetes | AKS credentials, RBAC, audit logs | planned (WP-35) |
| Security posture & alerts | Defender for Cloud, secure score, alerts | planned (WP-35) |
| Policy & governance | Azure Policy, locks, tags | planned (WP-35) |
| Incident response & forensics | Contain identities, isolate VMs, snapshot disks | planned (WP-35) |
| Persistence & threat hunting | Rogue role assignments, app credentials, automation runbooks | planned (WP-35) |
| Troubleshooting | Auth errors, quota, provider registration, NSG effective rules | planned (WP-35) |

## All Azure entries

<!-- cc:index platforms="Azure" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Azure Cloud Infrastructure and Resource Administration](../../tasks/administration/cloud-azure-resource-management.md) | Workflow | Azure, Entra ID | PowerShell, Bash | Administration |
| [CISA SCuBA Microsoft 365 and Azure Baseline Compliance](../../tasks/assurance/cisa-scuba-compliance.md) | Workflow | Microsoft 365, Azure, Entra ID | PowerShell | Assurance, Compliance, Hardening |
| [Hunting Cloud Identity Persistence in Entra ID and Microsoft 365](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../../tasks/incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies](../../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | KQL, SPL, PowerShell | Threat Hunting, Incident Response, Investigation |
| [Assurance Check — Azure External Guest Access & Permissions](../../tasks/assurance/azure-guest-access-audit.md) | Entry | Entra ID, Azure, Microsoft 365 | PowerShell | Assurance, Hardening, Administration |
| [Assurance Check — Azure Network Security Group Compliance](../../tasks/assurance/azure-nsg-compliance.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Detection Rule — Network Flood (DoS / DDoS)](../../detection/sigma/dos-flood.md) | Entry | Azure, Splunk | Sigma, KQL, SPL | Detection Engineering, Incident Response |
| [Fundamentals — Azure Policy & Governance Baselines](../../fundamentals/cloud/azure-policy.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Fundamentals — Azure Virtual Network (VNet) Security](../../fundamentals/cloud/azure-vnet-security.md) | Entry | Azure | PowerShell | Hardening, Administration |
| [Fundamentals — NIST Cybersecurity Framework (CSF) 2.0](../../fundamentals/grc/nist-csf-2.md) | Entry | Windows, Linux, Microsoft 365, Azure | PowerShell, Bash, Python | Assurance, Hardening, Administration, Incident Response |
| [Fundamentals — Regulatory Compliance & Framework Cross-Walk](../../fundamentals/grc/regulatory-frameworks.md) | Entry | Windows, Linux, Azure, Microsoft 365 | PowerShell, Bash, Python | Assurance, Hardening, Administration |
| [Sigma Rules for Cloud Identity and Entra ID Attacks](../../detection/sigma/cloud-identity-rules.md) | Entry | Entra ID, Microsoft 365, Azure | Sigma | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious Azure RBAC Modification](../../detection/spl/azure-rbac-modification.md) | Entry | Azure, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [Threat Actor Intelligence Profiles & TTP Reference Cards](../../references/threat-actor-profiles.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft 365 | KQL, SPL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Access Control Models (ACL, DAC, MAC, RBAC, ABAC)](../../fundamentals/concepts/access-control-models.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Administration, Assurance |
| [Cloud-Native Security (Containers, Kubernetes, Microservices)](../../fundamentals/concepts/cloud-native-security.md) | Concept | Linux, Azure | Bash, KQL | Hardening, Threat Hunting, Assurance |
| [Cyber Law (CFAA, ECPA, FISA, PATRIOT Act, SOX, FISMA, FedRAMP)](../../fundamentals/concepts/cyber-law.md) | Concept | Windows, Azure | PowerShell | Compliance, Assurance, Incident Response |
| [Defense in Depth and Secure Network Design](../../fundamentals/concepts/defense-in-depth.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Assurance |
| [Denial of Service (DoS and DDoS)](../../fundamentals/concepts/denial-of-service.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Incident Response, Troubleshooting, Hardening |
| [Identity and Access Management (IAM, PAM, Directory Services)](../../fundamentals/concepts/identity-access-management.md) | Concept | Windows Server, Entra ID, Azure | PowerShell, KQL | Administration, Hardening, Assurance |
| [Security Information and Event Management (SIEM)](../../fundamentals/concepts/siem.md) | Concept | Splunk, Microsoft Defender, Azure | SPL, KQL | Detection Engineering, Investigation, Threat Hunting |
| [Security Standards Map (ISO/IEC 27000 series, NIST SP 800)](../../fundamentals/concepts/security-standards-map.md) | Concept | Windows, Linux, Azure | PowerShell | Compliance, Assurance, Hardening |

<!-- /cc:index -->
