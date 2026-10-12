---
title: Amazon Web Services (AWS)
type: index
---

# Amazon Web Services (AWS)

Amazon Web Services: Organizations, IAM, EC2, VPC, S3, CloudTrail, KMS, EKS, GuardDuty and Security Hub.

!!! info "Tools"
    Use the **AWS CLI v2** (`aws`) with named SSO profiles; **AWS Tools for PowerShell** and **boto3** cover the same APIs. Query CloudTrail with **CloudTrail Lake** or **Athena (SQL)**.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Find out who I am and which credentials the CLI used | [CLI & authentication → Who am I?](cli-authentication.md#3-who-am-i) |
| Find access keys older than 90 days | [IAM → Credential report](identity-access.md#2-credential-report) |
| See who deleted or changed a resource | [CloudTrail → Quick lookups](audit-logging.md#1-quick-lookups-event-history) |
| Isolate an EC2 instance and snapshot its volumes | [Incident response](incident-response.md#2-isolate-an-instance) |
| Kill stolen role credentials | [Incident response → Contain the identity](incident-response.md#1-contain-the-identity) |
| Find public S3 buckets | [S3](storage.md#2-find-exposed-buckets) |
| Hunt for backdoor users, keys and trust policies | [Persistence & threat hunting](persistence-hunting.md) |
| Decode an `AccessDenied` error | [Troubleshooting](troubleshooting.md#1-accessdenied-and-authentication-errors) |

## Topics

Every cloud uses the same topic set, so the Azure, AWS and GCP pages line up side by side.

| Topic | Covers | Page |
| --- | --- | --- |
| CLI, SDK & authentication | aws configure, SSO profiles, assume-role, IMDSv2 | [CLI & Authentication](cli-authentication.md) |
| Resource hierarchy & inventory | Organizations, OUs, accounts; Resource Explorer, Config | [Organizations & Inventory](resource-hierarchy.md) |
| Identity & access | IAM users, roles, policies, Access Analyzer | [IAM](identity-access.md) |
| Compute | EC2, SSM Run Command, instance profiles | [EC2 & Systems Manager](compute.md) |
| Networking | VPCs, security groups, NACLs, flow logs | [VPC & Security Groups](networking.md) |
| Storage & data exposure | S3 buckets, policies, Block Public Access | [S3](storage.md) |
| Audit logging | CloudTrail, organization trails, CloudTrail Lake | [CloudTrail](audit-logging.md) |
| Monitoring & log queries | CloudWatch Logs, Logs Insights, Athena | [CloudWatch & Athena](monitoring-logs.md) |
| Keys & secrets | KMS, Secrets Manager, Parameter Store | [KMS & Secrets Manager](keys-secrets.md) |
| Kubernetes | EKS access entries, IRSA / Pod Identity | [EKS](kubernetes.md) |
| Security posture & alerts | Security Hub, GuardDuty, Inspector | [GuardDuty & Security Hub](security-posture.md) |
| Policy & governance | SCPs, Config rules, tag policies | [SCPs & Config](policy-governance.md) |
| Incident response & forensics | Revoke sessions, quarantine EC2, EBS snapshots | [Incident Response](incident-response.md) |
| Persistence & threat hunting | Backdoor IAM users/keys, Lambda, rogue roles | [Persistence & Hunting](persistence-hunting.md) |
| Troubleshooting | AccessDenied decoding, IAM simulator, Reachability Analyzer | [Troubleshooting](troubleshooting.md) |

## All AWS entries

<!-- cc:index platforms="AWS" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Amazon CloudWatch, Logs Insights & Athena](monitoring-logs.md) | Entry | AWS | Bash, Python | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Amazon EC2 & Systems Manager (Compute)](compute.md) | Entry | AWS | Bash, PowerShell | Administration, Investigation, Incident Response |
| [Amazon Elastic Kubernetes Service (EKS)](kubernetes.md) | Entry | AWS | Bash | Administration, Hardening, Investigation, Incident Response |
| [Amazon S3 & Data Exposure](storage.md) | Entry | AWS | Bash | Administration, Hardening, Investigation, Incident Response |
| [AWS CLI, SDKs & Authentication](cli-authentication.md) | Entry | AWS | Bash, PowerShell, Python | Administration, Automation, Incident Response |
| [AWS CloudTrail (Audit Logging)](audit-logging.md) | Entry | AWS | Bash, Python | Investigation, Incident Response, Forensics, Hardening |
| [AWS Identity & Access (IAM)](identity-access.md) | Entry | AWS | Bash, Python | Administration, Hardening, Investigation, Assurance |
| [AWS Incident Response & Forensics](incident-response.md) | Entry | AWS | Bash | Incident Response, Forensics, Investigation |
| [AWS KMS, Secrets Manager & Parameter Store](keys-secrets.md) | Entry | AWS | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [AWS Networking (VPC, Security Groups, Flow Logs)](networking.md) | Entry | AWS | Bash | Administration, Troubleshooting, Investigation, Hardening |
| [AWS Organizations, Accounts & Inventory](resource-hierarchy.md) | Entry | AWS | Bash, Python | Administration, Investigation, Assurance |
| [AWS Persistence & Threat Hunting](persistence-hunting.md) | Entry | AWS | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [AWS SCPs, Config Rules & Governance](policy-governance.md) | Entry | AWS | Bash | Hardening, Assurance, Administration, Governance |
| [AWS Security Hub, GuardDuty & Inspector (Posture & Alerts)](security-posture.md) | Entry | AWS | Bash | Assurance, Hardening, Investigation, Incident Response |
| [AWS Troubleshooting](troubleshooting.md) | Entry | AWS | Bash | Troubleshooting, Administration |

<!-- /cc:index -->
