---
title: Shared Responsibility Model
type: concept
platforms: [Azure, AWS, GCP]
languages: [PowerShell, Bash]
tasks: [Hardening, Governance, Assurance]
category: Cloud Security
security_domain: Cloud
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, cloud, shared-responsibility, iaas, paas, saas, cloud-security]
aliases: [cloud shared responsibility, IaaS security, PaaS security, SaaS security, customer responsibility in cloud]
difficulty: basic
verified: false
---

# Shared Responsibility Model
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** cloud security is split between the provider and the customer — the dividing line shifts depending on the service model, and most cloud breaches happen in the customer's half.

## What it is

Every major cloud provider (AWS, Azure, GCP) publishes a shared responsibility model: a division of who is accountable for which security controls. The model shifts the boundary based on the service type:

- **IaaS (Infrastructure as a Service)** — the provider secures the physical facilities, hypervisor, and network fabric. The customer is responsible for the operating system, runtime, middleware, application, and data.
- **PaaS (Platform as a Service)** — the provider additionally manages the OS, runtime, and middleware. The customer is responsible for the application code, configuration, and data.
- **SaaS (Software as a Service)** — the provider manages the entire stack. The customer is responsible for access management, data it uploads, and how it configures the application.

The model is not a license to stop thinking about security once a workload is in the cloud. It defines ownership — and where most organisations fail is underestimating how much the customer still owns.

## How it works

```text
                Physical data centre
                Network fabric          │ Provider always owns
                Hypervisor / hardware   │
────────────────────────────────────────┤
                Operating system        │ IaaS: Customer
                Runtime / middleware    │ PaaS: Provider
                Application             │ IaaS/PaaS: Customer
                Data                    │ Always Customer
────────────────────────────────────────┤
                Identity and access     │ Always Customer
                Configuration           │ Always Customer
```

**IaaS (e.g. AWS EC2, Azure VM, Google Compute Engine):** You receive a virtual machine with configurable CPU, memory, storage, and an operating system of your choice. You manage everything from the OS inwards: applying patches, configuring the firewall rules on the instance, installing and hardening applications. The cloud network is yours to configure — by default, inbound traffic is blocked, but every open port you add is your responsibility.

**PaaS (e.g. Azure App Service, AWS Elastic Beanstalk, GCP App Engine):** The provider handles the OS and runtime. You deploy code and configuration. You cannot access the underlying VM but you also do not patch it — the provider does. Your surface area is the application code, environment variables (where secrets often leak), and the access controls around the deployment pipeline.

**SaaS (e.g. Microsoft 365, Google Workspace, Salesforce):** The entire stack is managed. The customer's security responsibilities concentrate on identity (who has access, which permissions, which MFA policies) and data governance (what data the application holds, where it is stored, who can export it). Misconfigured sharing settings and over-permissioned service accounts are the leading causes of SaaS data exposure.

**What customers consistently miss regardless of model:**
1. **Identity and access management** — every cloud model requires the customer to configure users, roles, and least-privilege policies. A publicly accessible storage bucket or a service account with owner-level rights is a customer misconfiguration.
2. **Data classification and encryption in transit** — providers offer encryption at rest by default in most services, but enabling TLS for custom application endpoints and classifying what data lives where are customer tasks.
3. **Logging and monitoring** — the provider records its own infrastructure events. Enabling application-level logging, shipping those logs to a SIEM, and setting retention policies are customer responsibilities.
4. **Network configuration** — security groups, VPC configurations, and firewall rules are customer-managed. A permissive `0.0.0.0/0` inbound rule is not the provider's mistake.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1530](https://attack.mitre.org/techniques/T1530/) — Data from Cloud Storage · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) — Valid Accounts: Cloud Accounts |
| **What it leads to** | exposed storage objects, over-permissioned cloud identities, unmonitored data exfiltration |
| **Where defenders meet it** | cloud security posture management (CSPM) findings, compliance audits, post-incident reviews |

## Do it

```bash
# AWS: list S3 buckets with public access block status
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I{} aws s3api get-public-access-block --bucket {}

# Azure: check storage accounts that allow public blob access
az storage account list --query "[].{Name:name, PublicAccess:allowBlobPublicAccess}" -o table
```

```powershell
# Azure: list VMs with no disk encryption (customer responsibility in IaaS)
Get-AzVM | ForEach-Object {
    $enc = Get-AzVMDiskEncryptionStatus -ResourceGroupName $_.ResourceGroupName -VMName $_.Name -EA SilentlyContinue
    [PSCustomObject]@{ VM = $_.Name; OSDiskEncrypted = $enc.OsVolumeEncrypted }
}
```

> [!CAUTION]
> **SECURITY WARNING:** These commands query your cloud environment. Run with read-only roles (`Reader`, `SecurityReader`). Never run in production without change-management approval.

## See it

| Source | What you see |
| :--- | :--- |
| CSPM (Defender for Cloud, AWS Security Hub) | Misconfigured resources flagged against CIS benchmarks |
| Cloud audit logs (CloudTrail, Azure Monitor, Cloud Audit Logs) | API calls to modify IAM policies, security groups, or storage permissions |
| SIEM | Unexpected cross-region data access; service account activity outside business hours |

## Detect it

- Harden: [Cloud-Native Security](cloud-native-security.md)
- Reference: [Azure / Entra ID Identity Posture Audit](../../platforms/azure/identity-posture-audit.md)
- Governance: [Risk Management, Policies and Compliance Audits](risk-management-governance.md)

## Related concepts

- [Cloud-Native Security](cloud-native-security.md)
- [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- [CIA Triad and Least Privilege](cia-triad.md)
