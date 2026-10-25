---
title: Enumerate Cloud Attack Surface across AWS, Azure and GCP
type: workflow
platforms: [AWS, Azure, GCP]
languages: [Bash, Python]
tasks: [Assessment]
category: Workflow
security_domain: Cloud
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [cloud, aws, azure, gcp, enumeration, attack-surface, iam, imds, ssrf, metadata, storage-exposure, public-buckets, scoutsuite, prowler, role-enumeration, privilege-escalation]
aliases: [cloud enumeration, cloud attack surface, aws enumeration, azure enumeration, gcp enumeration, public s3 buckets, iam privilege escalation, instance metadata ssrf, imds, scoutsuite, prowler, cloud pentest recon, find public cloud storage]
difficulty: intermediate
verified: false
---

# Enumerate Cloud Attack Surface across AWS, Azure and GCP
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Cloud testing runs against accounts and may trip the provider's abuse controls.
> 1. Test **only** accounts/subscriptions/projects you own or are explicitly authorized to assess, and
>    confirm whether the provider requires notification for the activity.
> 2. Use **read-only** credentials where possible; enumeration should not create, modify, or delete
>    resources. `--dry-run`/describe calls only unless a change is explicitly in scope.
> 3. API calls are logged (CloudTrail / Azure Activity / Cloud Audit Logs) and metered — stay inside
>    the agreed window.
> 4. Treat the output as sensitive — it maps IAM paths and exposed data.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands follow the documented syntax of the provider CLIs and auditing tools (ScoutSuite, Prowler)
    but have not been lab-run for this page. Confirm flags against each tool's `--help` and the
    provider docs. Remove this block when `verified: true`.

**Trigger:** you have authorized access to a cloud environment (or are assessing an organization's
public cloud footprint) and need to map the attack surface — exposed storage, over-permissioned
identities, and metadata/SSRF paths — and document the misconfigurations.

**Goal:** work from external exposure → authenticated identity & resource enumeration → the
cloud-specific escalation paths (IAM privilege escalation, instance-metadata SSRF). This is
**enumeration**; remediation maps to [Cloud-Native Security](../fundamentals/concepts/cloud-native-security.md)
and the [Azure security baseline](../tasks/hardening/cloud-azure-security-baseline.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| External exposure | DNS, bucket probes | Public storage, exposed endpoints, no creds needed |
| Who am I | `aws sts`, `az account`, `gcloud auth` | The identity and account/subscription/project you hold |
| Resource & IAM enum | provider CLIs, ScoutSuite, Prowler | Resources, roles, policies, public settings |
| Escalation paths | IAM analysis, IMDS | Privilege-escalation chains and SSRF-reachable credentials |

## 1. External exposure (unauthenticated)

Public misconfigurations need no credentials — check them first:

```bash
# AWS S3: does a named bucket exist and is it publicly listable?
BUCKET="acme-backups"
curl -s -o /dev/null -w "%{http_code}\n" "https://${BUCKET}.s3.amazonaws.com/"
aws s3 ls "s3://${BUCKET}" --no-sign-request 2>&1 | head

# Azure Blob: public container listing
curl -s "https://acmestorage.blob.core.windows.net/backups?restype=container&comp=list" | head

# GCP Storage: public bucket object listing
curl -s "https://storage.googleapis.com/storage/v1/b/acme-public/o" | head
```

A `200` with a listing (or `--no-sign-request` returning objects) is a public-storage finding. Combine
with subdomain/DNS recon from [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) to find the
bucket and endpoint names in the first place.

## 2. Establish identity (authenticated)

With authorized credentials configured, confirm exactly who you are before enumerating:

```bash
# AWS
aws sts get-caller-identity

# Azure
az account show --output json
az ad signed-in-user show --output json 2>/dev/null

# GCP
gcloud auth list
gcloud config list
```

Record the principal, the account/subscription/project, and whether the credential is a user, a role,
or a service account — it frames everything below.

## 3. Resource and IAM enumeration

Run a read-only auditor for breadth, then drill in with the CLI:

```bash
# ScoutSuite: multi-cloud read-only posture assessment (writes an HTML report)
scout aws    # or: scout azure | scout gcp

# Prowler: hundreds of AWS/Azure/GCP checks mapped to CIS and provider best practice
prowler aws -M csv json-ocsf
```

```bash
# AWS: who can do what — the IAM surface
aws iam list-users; aws iam list-roles
aws iam list-policies --scope Local
# Public exposure settings that commonly leak
aws s3api get-public-access-block --bucket "$BUCKET" 2>&1
```

```bash
# Azure: roles and assignments on the current scope
az role assignment list --all --output table
az storage account list --query "[].{name:name, public:allowBlobPublicAccess}" -o table

# GCP: project IAM policy (who holds which roles)
gcloud projects get-iam-policy "$(gcloud config get-value project)" --format=json
```

Look for identities with wildcard or admin-equivalent policies (`*:*`, `Owner`, `roles/owner`), public
storage settings left on, and service accounts with far more rights than their workload needs.

## 4. Cloud-specific escalation paths

| Path | Where it lives | Note it as |
| :--- | :--- | :--- |
| IAM privilege escalation | `iam:PassRole` + `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, etc. | Over-permissioned IAM |
| Instance-metadata SSRF (IMDS) | A web app that can be made to fetch `169.254.169.254` | Credential exposure via SSRF |
| Over-scoped service account | A VM/function whose attached identity can touch unrelated resources | Workload identity over-reach |
| Public snapshot / image | Shared EBS/managed-disk snapshots, public AMIs | Data exposure |

The IMDS path ties directly to the web assessment: an [SSRF](../fundamentals/web-apps/ssrf-defense.md)
in a cloud-hosted app that reaches the metadata endpoint can return temporary credentials. On AWS,
confirm whether the instance still allows **IMDSv1** (unauthenticated) rather than enforcing IMDSv2:

```bash
# From an authorized instance / SSRF proof-of-concept only:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

IMDSv2 requires a token (`PUT /latest/api/token`), which defeats most SSRF — "IMDSv1 still enabled" is
itself a finding.

## 5. Record findings

Keep the ScoutSuite/Prowler reports and CLI output as evidence. For each finding, write **what** (the
misconfig / over-permission), **where** (ARN / resource ID / principal), **evidence** (the policy or
CLI output), **severity** (what the identity or exposure actually reaches), and **fix** (least
privilege, block public access, enforce IMDSv2) — mapped to the cloud hardening baseline.

## Detect it

The authenticated enumeration above is **read-only but fully logged** — every describe/list call lands
in CloudTrail / Azure Activity / Cloud Audit Logs, which is exactly what drives the cloud detection
content on the [Detection](../detection/index.md) tab. Pair each technique with what catches it:

| Offensive technique here | Detect it with |
| :--- | :--- |
| IAM/role enumeration and permission mapping (§3) | [Sigma — Cloud Identity Rules](../detection/sigma/cloud-identity-rules.md) · [SPL — Azure RBAC Modification](../detection/spl/azure-rbac-modification.md) |
| Escalation paths that touch MFA or security settings (§4) | [SPL — MFA Deletion / Security-Control Tampering](../detection/spl/mfa-deletion.md) |
| External exposure probing of public endpoints (§1) | [KQL — Network Event Hunting](../detection/kql/network-events.md) |

Describe/list calls at enumeration volume, from a new principal or an unusual network, are the pattern
the defender hunts for — which is why §0's coordinated window matters.

## Notes

- **Read-only, logged, metered.** Prefer describe/list calls; every action lands in CloudTrail / Azure
  Activity / Cloud Audit Logs and may alert the owner — coordinate the window.
- **Public exposure first.** Unauthenticated bucket and endpoint checks are the fastest, lowest-risk
  wins and need no credentials.
- **Identity is the perimeter.** In cloud the escalation is almost always an IAM path, not a software
  bug — spend the time on policy analysis (`iam:PassRole` chains, wildcard grants) over port scanning.
- Install notes: the provider CLIs (`awscli`, `azure-cli`, `google-cloud-sdk`) plus `scoutsuite` and
  `prowler` install via `pip`/package managers; all run from Linux.

## Related

- [Offensive — Overview](index.md)
- [Web Application Assessment](web-application-assessment.md) — SSRF to IMDS
- [Network & infrastructure enumeration](network-infrastructure-enumeration.md)
- Reference: [Cloud-Native Security](../fundamentals/concepts/cloud-native-security.md) · [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Identity & Access Management](../fundamentals/concepts/identity-access-management.md)
- Defensive counterparts: [Azure security baseline](../tasks/hardening/cloud-azure-security-baseline.md) · [AWS security baseline](../tasks/hardening/cloud-aws-security-baseline.md) · [GCP security baseline](../tasks/hardening/cloud-gcp-security-baseline.md) · [SSRF defense](../fundamentals/web-apps/ssrf-defense.md)

## External Resources & White Papers

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — multi-cloud security auditing
- [Prowler](https://github.com/prowler-cloud/prowler) — AWS/Azure/GCP security assessment
- [AWS IMDSv2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [MITRE ATT&CK — Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
