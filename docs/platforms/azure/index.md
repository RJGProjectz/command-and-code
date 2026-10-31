---
title: Azure
type: index
---

# Azure

Microsoft Azure infrastructure: subscriptions, RBAC, VMs, networking, storage, Key Vault, AKS, Defender for Cloud and Azure Policy. Identity itself (users, sign-ins, Conditional Access) lives under [Microsoft 365 → Entra ID](../microsoft-365/entra.md).

!!! info "Tools"
    Use the **Azure CLI** (`az`) or the **Az PowerShell** module (`Az.Accounts`, `Az.Resources`, ...). Run queries over logs in **Log Analytics (KQL)**. AzureRM is retired; do not build new automation on it.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Find who has Owner on a subscription | [Identity & access → List role assignments](identity-access.md#2-list-role-assignments) |
| See who deleted or changed a resource | [Audit logging → Investigation queries](audit-logging.md#3-investigation-queries-azureactivity) |
| Isolate a VM and snapshot its disks | [Incident response](incident-response.md#2-isolate-a-vm) |
| Find public blob containers and leaked SAS tokens | [Storage](storage.md#2-anonymous-public-containers) |
| Find who read Key Vault secrets | [Key Vault → Audit secret access](keys-secrets.md#7-audit-secret-access) |
| Hunt for backdoors after a compromise | [Persistence & threat hunting](persistence-hunting.md) |
| Decode an `AuthorizationFailed` error | [Troubleshooting](troubleshooting.md#2-authorizationfailed-which-permission-is-missing) |

## Topics

Every cloud uses the same topic set, so the Azure, AWS and GCP pages line up side by side.

| Topic | Covers | Page |
| --- | --- | --- |
| CLI, SDK & authentication | az / Az PowerShell login, service principals, managed identity | [CLI & Authentication](cli-authentication.md) |
| Resource hierarchy & inventory | Tenant, management groups, subscriptions, resource groups; Resource Graph | [Resource Hierarchy & Inventory](resource-hierarchy.md) |
| Identity & access | Azure RBAC, PIM, managed identities | [Identity & Access (RBAC)](identity-access.md) |
| Compute | Virtual machines, Run Command, extensions | [Virtual Machines](compute.md) |
| Networking | VNets, NSGs, flow logs, Azure Firewall | [Networking](networking.md) |
| Storage & data exposure | Storage accounts, SAS tokens, public blobs | [Storage](storage.md) |
| Audit logging | Activity Log, Entra sign-in/audit logs, diagnostic settings | [Audit Logging](audit-logging.md) |
| Monitoring & log queries | Azure Monitor, Log Analytics, KQL | [Monitor & Log Analytics](monitoring-logs.md) |
| Keys & secrets | Key Vault keys, secrets, access policies vs RBAC | [Key Vault](keys-secrets.md) |
| Kubernetes | AKS credentials, RBAC, audit logs | [AKS](kubernetes.md) |
| Security posture & alerts | Defender for Cloud, secure score, alerts | [Defender for Cloud](security-posture.md) |
| Policy & governance | Azure Policy, locks, tags | [Policy & Locks](policy-governance.md) |
| Incident response & forensics | Contain identities, isolate VMs, snapshot disks | [Incident Response](incident-response.md) |
| Persistence & threat hunting | Rogue role assignments, app credentials, automation runbooks | [Persistence & Hunting](persistence-hunting.md) |
| Troubleshooting | Auth errors, quota, provider registration, NSG effective rules | [Troubleshooting](troubleshooting.md) |

## All Azure entries

<!-- cc:index platforms="Azure" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Azure / Entra ID Identity Posture Audit](../../tasks/assurance/azure-posture-audit.md) | Workflow | Azure, Entra ID | PowerShell | Assurance, Hardening, Administration |
| [Azure Cloud Infrastructure and Resource Administration](../../tasks/administration/cloud-azure-resource-management.md) | Workflow | Azure, Entra ID | PowerShell, Bash | Administration |
| [CISA SCuBA Microsoft 365 and Azure Baseline Compliance](../../tasks/assurance/cisa-scuba-compliance.md) | Workflow | Microsoft 365, Azure, Entra ID | PowerShell | Assurance, Compliance, Hardening |
| [Credential Rotation After a Compromise](../../tasks/incident-response/credential-rotation-after-compromise.md) | Workflow | Active Directory, Windows Server, Linux, Entra ID, Azure | PowerShell, Bash, CMD | Incident Response, Administration |
| [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md) | Workflow | AWS, Azure, GCP | Bash, Python | Assessment |
| [Hunting Cloud Identity Persistence in Entra ID and Microsoft 365](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../../tasks/incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies](../../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | KQL, SPL, PowerShell | Threat Hunting, Incident Response, Investigation |
| [Assurance Check — Azure External Guest Access & Permissions](../../tasks/assurance/azure-guest-access-audit.md) | Entry | Entra ID, Azure, Microsoft 365 | PowerShell | Assurance, Hardening, Administration |
| [Assurance Check — Azure Network Security Group Compliance](../../tasks/assurance/azure-nsg-compliance.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Azure Audit Logging (Activity Log & Diagnostic Settings)](audit-logging.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Investigation, Incident Response, Forensics, Hardening |
| [Azure CLI, Az PowerShell & Authentication](cli-authentication.md) | Entry | Azure | Bash, PowerShell | Administration, Automation, Incident Response |
| [Azure Identity & Access (RBAC, PIM, Managed Identities)](identity-access.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Assurance |
| [Azure Incident Response & Forensics](incident-response.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Incident Response, Forensics, Investigation |
| [Azure Key Vault (Keys, Secrets & Certificates)](keys-secrets.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Kubernetes Service (AKS)](kubernetes.md) | Entry | Azure | Bash, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Monitor & Log Analytics Queries](monitoring-logs.md) | Entry | Azure | Bash, PowerShell, KQL | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Azure Networking (VNets, NSGs, Flow Logs, Firewall)](networking.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Troubleshooting, Investigation, Hardening |
| [Azure Persistence & Threat Hunting](persistence-hunting.md) | Entry | Azure, Entra ID | KQL, Bash, PowerShell | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Azure Policy, Locks & Governance](policy-governance.md) | Entry | Azure | Bash, PowerShell, KQL | Hardening, Assurance, Administration, Governance |
| [Azure Resource Hierarchy & Inventory](resource-hierarchy.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Assurance |
| [Azure Storage & Data Exposure](storage.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Troubleshooting](troubleshooting.md) | Entry | Azure | Bash, PowerShell | Troubleshooting, Administration |
| [Azure Virtual Machines (Compute)](compute.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Incident Response |
| [Detection Rule — Network Flood (DoS / DDoS)](../../detection/sigma/dos-flood.md) | Entry | Azure, Splunk | Sigma, KQL, SPL | Detection Engineering, Incident Response |
| [Firewalls & Network Layer Controls](../../fundamentals/web-apps/firewall-and-network-controls.md) | Entry | Linux, Windows, AWS, Azure, GCP | Bash, PowerShell | Hardening, Assurance, Assessment |
| [Fundamentals — Azure Policy & Governance Baselines](../../fundamentals/cloud/azure-policy.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Fundamentals — Azure Virtual Network (VNet) Security](../../fundamentals/cloud/azure-vnet-security.md) | Entry | Azure | PowerShell | Hardening, Administration |
| [Fundamentals — NIST Cybersecurity Framework (CSF) 2.0](../../fundamentals/grc/nist-csf-2.md) | Entry | Windows, Linux, Microsoft 365, Azure | PowerShell, Bash, Python | Assurance, Hardening, Administration, Incident Response |
| [Fundamentals — Regulatory Compliance & Framework Cross-Walk](../../fundamentals/grc/regulatory-frameworks.md) | Entry | Windows, Linux, Azure, Microsoft 365 | PowerShell, Bash, Python | Assurance, Hardening, Administration |
| [KQL — Web Attacks (SQLi, XSS, Path Traversal & Login Brute-Force)](../../detection/kql/web-attacks.md) | Entry | Azure | KQL | Detection Engineering, Threat Hunting |
| [Microsoft Defender for Cloud (Posture & Alerts)](security-posture.md) | Entry | Azure, Microsoft Defender | Bash, PowerShell, KQL | Assurance, Hardening, Investigation, Incident Response |
| [Sigma Rules for Cloud Identity and Entra ID Attacks](../../detection/sigma/cloud-identity-rules.md) | Entry | Entra ID, Microsoft 365, Azure | Sigma | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious Azure RBAC Modification](../../detection/spl/azure-rbac-modification.md) | Entry | Azure, Splunk | SPL | Detection Engineering, Threat Hunting |
| [WAF Fundamentals & Tuning](../../tasks/hardening/waf-fundamentals-and-tuning.md) | Entry | Linux, AWS, Azure | Bash | Hardening, Assurance, Detection Engineering |
| [Web Telemetry, Logging & Auditing Standards](../../tasks/hardening/web-telemetry-logging-standards.md) | Entry | Linux, Windows, AWS, Azure | Bash, PowerShell | Hardening, Assurance, Detection Engineering, Governance |
| [Cloud Incident Response Cheat Sheet (Printable)](../../references/cloud-ir-cheat-sheet.md) | Reference | AWS, Azure, GCP | Bash, PowerShell | Incident Response, Investigation, Forensics |
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
