---
title: Google Cloud (GCP)
type: index
---

# Google Cloud (GCP)

Google Cloud: organization and project hierarchy, Cloud IAM, Compute Engine, VPC, Cloud Storage, Cloud Audit Logs, Cloud KMS, GKE and Security Command Center.

!!! info "Tools"
    Use the **Google Cloud CLI** (`gcloud`, `gcloud storage`, `bq`). Query logs with the **Logging query language** in Logs Explorer or `gcloud logging read`.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Find out who I am and which project gcloud uses | [CLI & authentication → Who am I?](cli-authentication.md#3-who-am-i) |
| Find downloadable service-account keys | [Cloud IAM → Service accounts and keys](identity-access.md#3-service-accounts-and-keys) |
| See who deleted or changed a resource | [Cloud Audit Logs → Quick lookups](audit-logging.md#1-quick-lookups) |
| Isolate a VM and snapshot its disks | [Incident response](incident-response.md#2-isolate-a-vm) |
| Kill a leaked service-account key | [Incident response → Contain the identity](incident-response.md#1-contain-the-identity) |
| Find public Cloud Storage buckets | [Cloud Storage](storage.md#2-find-exposed-buckets) |
| Hunt for backdoor keys, grants and functions | [Persistence & threat hunting](persistence-hunting.md) |
| Decode a `PERMISSION_DENIED` error | [Troubleshooting](troubleshooting.md#1-permission-denied-and-authentication-errors) |

## Topics

Every cloud uses the same topic set, so the Azure, AWS and GCP pages line up side by side.

| Topic | Covers | Page |
| --- | --- | --- |
| CLI, SDK & authentication | gcloud auth, ADC, service-account impersonation | [CLI & Authentication](cli-authentication.md) |
| Resource hierarchy & inventory | Organization, folders, projects; Cloud Asset Inventory | [Resource Manager & Asset Inventory](resource-hierarchy.md) |
| Identity & access | Cloud IAM, service accounts, keys, Policy Analyzer | [Cloud IAM](identity-access.md) |
| Compute | Compute Engine, OS Login, metadata | [Compute Engine & OS Login](compute.md) |
| Networking | VPC, firewall rules, VPC flow logs | [VPC & Firewall Rules](networking.md) |
| Storage & data exposure | Cloud Storage buckets, uniform access, allUsers | [Cloud Storage](storage.md) |
| Audit logging | Cloud Audit Logs (Admin, Data Access), log sinks | [Cloud Audit Logs](audit-logging.md) |
| Monitoring & log queries | Cloud Logging, Logging query language, BigQuery | [Cloud Logging & BigQuery](monitoring-logs.md) |
| Keys & secrets | Cloud KMS, Secret Manager | [Cloud KMS & Secret Manager](keys-secrets.md) |
| Kubernetes | GKE, Workload Identity, audit logs | [GKE](kubernetes.md) |
| Security posture & alerts | Security Command Center findings | [Security Command Center](security-posture.md) |
| Policy & governance | Organization Policy constraints | [Organization Policy](policy-governance.md) |
| Incident response & forensics | Disable SA keys, isolate VMs, disk snapshots | [Incident Response](incident-response.md) |
| Persistence & threat hunting | SA keys, IAM bindings, Cloud Functions | [Persistence & Hunting](persistence-hunting.md) |
| Troubleshooting | Permission denied, API not enabled, Connectivity Tests | [Troubleshooting](troubleshooting.md) |

## All GCP entries

<!-- cc:index platforms="GCP" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md) | Workflow | AWS, Azure, GCP | Bash, Python | Assessment |
| [Firewalls & Network Layer Controls](../../fundamentals/web-apps/firewall-and-network-controls.md) | Entry | Linux, Windows, AWS, Azure, GCP | Bash, PowerShell | Hardening, Assurance, Assessment |
| [GCP Security Baseline — CIS Google Cloud Foundations Benchmark & Security Command Center](../../tasks/hardening/cloud-gcp-security-baseline.md) | Entry | GCP | Bash | Hardening, Assurance, Governance |
| [Google Cloud Audit Logs](audit-logging.md) | Entry | GCP | Bash | Investigation, Incident Response, Forensics, Hardening |
| [Google Cloud CLI, SDKs & Authentication](cli-authentication.md) | Entry | GCP | Bash, PowerShell, Python | Administration, Automation, Incident Response |
| [Google Cloud IAM (Identity & Access)](identity-access.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [Google Cloud Incident Response & Forensics](incident-response.md) | Entry | GCP | Bash | Incident Response, Forensics, Investigation |
| [Google Cloud KMS & Secret Manager](keys-secrets.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [Google Cloud Logging & BigQuery Log Queries](monitoring-logs.md) | Entry | GCP | Bash | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Google Cloud Organization Policy & Governance](policy-governance.md) | Entry | GCP | Bash | Hardening, Assurance, Administration, Governance |
| [Google Cloud Persistence & Threat Hunting](persistence-hunting.md) | Entry | GCP | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Google Cloud Resource Hierarchy & Inventory](resource-hierarchy.md) | Entry | GCP | Bash | Administration, Investigation, Assurance |
| [Google Cloud Storage (Buckets & Data Exposure)](storage.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Assurance |
| [Google Cloud Troubleshooting](troubleshooting.md) | Entry | GCP | Bash | Troubleshooting, Administration |
| [Google Cloud VPC & Firewall Rules](networking.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Google Compute Engine & OS Login](compute.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Google Kubernetes Engine (GKE)](kubernetes.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Security Command Center (GCP Posture & Alerts)](security-posture.md) | Entry | GCP | Bash | Assurance, Hardening, Investigation, Incident Response |
| [Cloud Incident Response Cheat Sheet (Printable)](../../references/cloud-ir-cheat-sheet.md) | Reference | AWS, Azure, GCP | Bash, PowerShell | Incident Response, Investigation, Forensics |

<!-- /cc:index -->
