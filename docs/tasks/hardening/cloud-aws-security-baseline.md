---
title: AWS Security Baseline — CIS AWS Foundations Benchmark & Security Hub
type: entry
platforms:
  - AWS
languages:
  - Bash
tasks:
  - Hardening
  - Assurance
  - Governance
category: Workflow
security_domain: Cloud
author: RJGProjectz
date_created: 2026-10-23
last_updated: 2026-10-23
verified: false
difficulty: advanced
tags:
  - cis-benchmark
  - cis-aws-foundations
  - nist-csf
  - baseline
  - aws
  - security-hub
  - guardduty
  - cloudtrail
  - aws-config
  - s3-block-public-access
  - iam-least-privilege
  - imdsv2
  - kms
aliases:
  - aws security baseline
  - harden aws account
  - cis aws foundations benchmark
  - aws security hub cis
  - imdsv2 enforcement
  - s3 block public access
  - cloudtrail all regions
  - aws root account mfa
---

# AWS Security Baseline — CIS AWS Foundations Benchmark & Security Hub
> **Created**: 2026-10-23T00:00:00Z
> **Last Modified**: 2026-10-23T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands. Before running any script:
> 1. Verify the script integrity and test in a non-production environment.
> 2. Ensure you are in a `Test` or `Dev` account (never the production payer/management account first).
> 3. AWS CLI has no universal `--dry-run` for write actions — **audit with `get`/`describe`/`list` first**, read the output, then apply the change.
> 4. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The commands and settings below follow the documented behaviour of the AWS CLI v2, the **CIS AWS
    Foundations Benchmark** and the AWS Security Hub / service docs cited at the foot of this page, but
    have **not** been lab-run against a live account for this page. CIS control numbers shift between
    benchmark versions — confirm each against the benchmark version your Security Hub standard reports.
    Account-wide changes (S3 Block Public Access, IMDSv2 required, SCPs, default-SG lockdown) **can break
    working workloads** — stage them, watch CloudTrail and application logs, and confirm before production.
    Remove this block when `verified: true`.

This is the **AWS counterpart** to the
[Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md), and the defensive answer to the
findings in [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md).
Each control below is tied, where relevant, to the offensive finding it closes — public storage,
over-permissioned IAM, and the SSRF → instance-metadata credential-theft pivot. Remediation principles
map to [Cloud-Native Security](../../fundamentals/concepts/cloud-native-security.md). Settings are
aligned with the **CIS AWS Foundations Benchmark** and **NIST Cybersecurity Framework (CSF) 2.0**
(`PR.AA-01`, `PR.DS-01`, `DE.CM-01`, `GV.PO-01`).

---

## 1. Compliance alignment matrix

| CIS AWS control (indicative) | NIST CSF 2.0 | Target service | Baseline enforcement standard | Closes offensive finding |
|:---|:---|:---|:---|:---|
| **1.4 / 1.5 / 1.6** | `PR.AA-01` | Root account | No root access keys; hardware/virtual MFA on root; stop using root for daily work. | Account takeover via root |
| **1.16 / 1.14** | `PR.AA-01` | IAM | No inline/attached `*:*` admin on users; roles over long-lived user keys; rotate/retire keys ≤ 90 days; permission boundaries. | Over-permissioned IAM · long-lived keys |
| **3.1 / 3.2** | `DE.CM-01` | CloudTrail | Multi-region trail with log-file validation enabled. | Unlogged activity |
| **3.5** | `DE.CM-01` | AWS Config | Config recorder enabled in all regions. | Drift / no inventory |
| **2.1.x** | `PR.DS-01` | S3 | Account-level **and** bucket-level Block Public Access; default encryption (SSE-KMS). | Public S3 buckets · data exposure |
| **4.x** | `DE.CM-01` | GuardDuty / Security Hub | GuardDuty on in all regions; Security Hub with the **CIS AWS Foundations Benchmark** standard. | Undetected credential abuse |
| **5.2 / 5.3 / 5.4** | `PR.IR-01` | VPC | No security group allows `0.0.0.0/0` → 22/3389; default SG denies all; VPC Flow Logs on. | Exposed management ports |
| **3.7 / 3.8** | `PR.DS-01` | KMS | Customer-managed KMS keys with rotation for encryption at rest. | Unencrypted data at rest |
| **IMDSv2 (AWS best practice)** | `PR.IR-01` | EC2 | `HttpTokens=required`, `HttpPutResponseHopLimit=1`. | **SSRF → IMDS credential theft** |

---

## 2. Root account lockdown & MFA

The management/root account is the highest-value identity. Audit it, then lock it down — closes the
"account takeover via root" path.

```bash
# Audit: is MFA active on root, and are there root access keys? [CIS 1.4-1.6]
aws iam get-account-summary \
  --query 'SummaryMap.{RootMFA:AccountMFAEnabled, RootAccessKeys:AccountAccessKeysPresent}'

# The credential report flags root usage and any root keys
aws iam generate-credential-report >/dev/null
aws iam get-credential-report --query 'Content' --output text | base64 -d | head -2
```

- **Enable MFA on root** and **delete any root access keys** from the IAM console (root MFA/key changes
  are console/root-session actions, not day-to-day CLI operations — do them manually and deliberately).
- Set a strong IAM **account password policy** and stop using root for anything but the few tasks that
  require it. Enforce "no root use" org-wide with an SCP (see §9).

---

## 3. IAM least privilege

The cloud perimeter is identity. Prefer **roles assumed short-term** over long-lived user access keys,
forbid admin wildcards, and bound what any principal can reach — this closes the **over-permissioned
IAM** and **long-lived key** findings from the enumeration page.

```bash
# 1. Find access keys older than 90 days (rotate or delete) [CIS 1.14]
aws iam generate-credential-report >/dev/null
aws iam get-credential-report --query 'Content' --output text | base64 -d \
  | awk -F, 'NR==1 || $9=="true"{print $1,$9,$10}'   # user, key1 active, key1 last rotated

# 2. Find customer-managed policies that grant *:* (full admin) [CIS 1.16]
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text | tr '\t' '\n' | while read -r arn; do
  ver=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn "$arn" --version-id "$ver" \
    --query "PolicyVersion.Document.Statement[?Effect=='Allow' && (Action=='*' || contains(Action, '*'))].Action" \
    --output text | grep -q '\*' && echo "WILDCARD: $arn"
done
```

- **No long-lived user keys for workloads.** EC2/Lambda/ECS use **IAM roles / instance profiles**; humans
  use **IAM Identity Center (SSO)** with short-lived sessions. Delete unused users and stale keys.
- **Permission boundaries** cap the maximum permissions a delegated admin can grant, so a `iam:PassRole`
  or policy-creation path cannot be escalated to full admin (the IAM-escalation chain in the offensive page).
- Run **IAM Access Analyzer** to surface resources shared outside the account and unused access.

```bash
# Attach a permission boundary when creating delegated principals
aws iam put-user-permissions-boundary \
  --user-name delegated-admin \
  --permissions-boundary arn:aws:iam::123456789012:policy/pb-developer-max
```

---

## 4. CloudTrail (all-region + log-file validation) & AWS Config

Without a trail, the enumeration and escalation above are **invisible**. A multi-region trail with log-file
validation is the baseline evidence source.

```bash
# Audit: is there a multi-region trail with log-file validation? [CIS 3.1 / 3.2]
aws cloudtrail describe-trails \
  --query 'trailList[].{Name:Name, MultiRegion:IsMultiRegionTrail, Validation:LogFileValidationEnabled}' \
  --output table

# Create a multi-region trail with validation and SSE-KMS on the log bucket
aws cloudtrail create-trail \
  --name org-baseline-trail \
  --s3-bucket-name my-cloudtrail-logs-123456789012 \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/<cloudtrail-key>
aws cloudtrail start-logging --name org-baseline-trail

# Enable AWS Config recording (inventory + drift) [CIS 3.5]
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[].{Name:name, Recording:recording}' --output table
```

Prefer an **organization trail** delivered to a locked logging account. Protect the log bucket with Block
Public Access, SSE-KMS, and a restrictive bucket policy; log-file validation lets you prove the trail was
not tampered with.

---

## 5. S3 Block Public Access & encryption

Public buckets are the single most common cloud data-exposure finding — the first thing the offensive page
checks unauthenticated. Enforce **Block Public Access at the account level** (overrides every bucket) and
default encryption. This closes the **public S3 bucket / data exposure** finding.

```bash
# Account-level Block Public Access — the backstop for every current and future bucket [CIS 2.1.x]
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Per-bucket Block Public Access (defence in depth)
aws s3api put-public-access-block \
  --bucket my-sensitive-bucket \
  --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Default encryption with a customer-managed KMS key
aws s3api put-bucket-encryption \
  --bucket my-sensitive-bucket \
  --server-side-encryption-configuration '{
    "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms",
      "KMSMasterKeyID":"arn:aws:kms:us-east-1:123456789012:key/<bucket-key>"},"BucketKeyEnabled":true}]}'

# Verify nothing is still public
aws s3api get-public-access-block --bucket my-sensitive-bucket
```

Account-level Block Public Access is the control to set first: it neutralises a misconfigured ACL or bucket
policy on any bucket, including ones created later.

---

## 6. GuardDuty & Security Hub (CIS AWS Foundations Benchmark standard)

Turn on continuous threat detection and the benchmark scoring that measures everything above — this is how
you **detect** the credential abuse that follows a successful enumeration.

```bash
# GuardDuty — threat detection (per region; enable org-wide via the delegated admin)
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Security Hub — enable, then subscribe the CIS AWS Foundations Benchmark standard [CIS 4.x scoring]
aws securityhub enable-security-hub --enable-default-standards
aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[].StandardsArn' --output text
# Subscribe the CIS AWS Foundations Benchmark standard explicitly if not already on:
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
      StandardsArn=arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0
```

Enable both in **every region** and aggregate findings to a single security/audit account. Security Hub's
CIS standard gives you a pass/fail score for the controls on this page; GuardDuty flags anomalous API use,
credential exfiltration and the `169.254.169.254` metadata-theft pattern.

---

## 7. VPC security groups & flow logs

Management ports open to the internet are the classic initial-access finding. Lock inbound SSH/RDP and the
default security group, and turn on flow logs for network evidence.

```bash
# Find security groups allowing 0.0.0.0/0 (or ::/0) inbound to 22 or 3389 [CIS 5.2 / 5.3]
aws ec2 describe-security-groups \
  --query "SecurityGroups[?IpPermissions[?(FromPort<=\`22\` && ToPort>=\`22\`) || (FromPort<=\`3389\` && ToPort>=\`3389\`)]].{Id:GroupId,Name:GroupName}" \
  --output table

# Remove a public SSH ingress rule once identified
aws ec2 revoke-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Default SG should permit no traffic [CIS 5.4] — strip its ingress/egress and never attach it.
# Enable VPC Flow Logs to CloudWatch Logs or S3 for network evidence
aws ec2 create-flow-logs \
  --resource-type VPC --resource-ids vpc-0123456789abcdef0 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /vpc/flowlogs --deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogsRole
```

Reach instances through **SSM Session Manager**, not public SSH/RDP — it needs no inbound rule at all and
every session is logged.

---

## 8. KMS encryption at rest

Use **customer-managed KMS keys** (CMKs) with rotation for data at rest, so access is governed by key
policy and logged in CloudTrail.

```bash
# Enable automatic annual rotation on a customer-managed key [CIS 3.8]
aws kms enable-key-rotation --key-id <cmk-key-id>
aws kms get-key-rotation-status --key-id <cmk-key-id>

# Require encryption by default for new EBS volumes in the region
aws ec2 enable-ebs-encryption-by-default
aws ec2 get-ebs-encryption-by-default
```

Scope key policies tightly (which principals may `kms:Decrypt`/`kms:Encrypt`), and prefer a CMK over the
AWS-managed default key wherever you need auditable, revocable access to the data it protects.

---

## 9. IMDSv2 enforcement & hop limit

This is the control that **directly closes the SSRF → instance-metadata credential-theft pivot** documented
in the offensive page. IMDSv1 answers any process (or any SSRF that reaches `169.254.169.254`) with the
instance role's temporary credentials. IMDSv2 requires a signed token via `PUT`, which defeats most SSRF,
and a **hop limit of 1** stops a container or proxy one network hop away from reaching it.

```bash
# Audit: which running instances still allow IMDSv1 (HttpTokens=optional)?
aws ec2 describe-instances \
  --query "Reservations[].Instances[?MetadataOptions.HttpTokens=='optional'].InstanceId" \
  --output text

# Enforce IMDSv2 and a hop limit of 1 on an existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled

# Make IMDSv2 the account default for newly launched instances in the region
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required --http-put-response-hop-limit 1
```

Enforce IMDSv2 org-wide with an SCP condition (`ec2:MetadataHttpTokens=required` on `ec2:RunInstances`), so
no account can launch an instance that accepts IMDSv1. Pair this with the SSRF fixes in
[SSRF defense](../../fundamentals/web-apps/ssrf-defense.md) — defence in depth closes the pivot from both ends.

---

## Detect it

The baseline above is prevention; pair it with detection. The repository's detection content is currently
Windows/endpoint and Azure/KQL focused — **there is no AWS-native CloudTrail/IAM detection page yet**, so
there is nothing honest to link here. In-account, the detections are:

- **GuardDuty** findings (§6) — anomalous API calls, credential exfiltration, the `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` pattern that fires on IMDS credential theft.
- **Security Hub** CIS standard score — a continuous pass/fail against the controls on this page.
- **CloudTrail + CloudWatch Logs / Athena** — metric filters and alarms for root login, policy changes, and failed/denied API calls (CIS 4.x).

A vendor-neutral AWS CloudTrail/IAM detection page is a reasonable follow-up for the Detection area.

## Offensive counterpart & related

- **Offensive counterpart:** [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md) — the findings this page closes (public buckets, IAM over-permission, IMDS/SSRF).
- [Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md) · [GCP Security Baseline](cloud-gcp-security-baseline.md) — the sibling cloud baselines.
- Reference: [Cloud-Native Security](../../fundamentals/concepts/cloud-native-security.md) · [Identity & Access Management](../../fundamentals/concepts/identity-access-management.md) · [SSRF defense](../../fundamentals/web-apps/ssrf-defense.md)
- AWS platform depth: [IAM](../../platforms/aws/identity-access.md) · [CloudTrail](../../platforms/aws/audit-logging.md) · [S3 & Data Exposure](../../platforms/aws/storage.md) · [GuardDuty & Security Hub](../../platforms/aws/security-posture.md) · [SCPs & Config](../../platforms/aws/policy-governance.md) · [VPC & Networking](../../platforms/aws/networking.md) · [KMS & Secrets](../../platforms/aws/keys-secrets.md)
- [Hardening — Overview](index.md)

## External resources

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) — the control catalogue this page aligns to.
- [AWS Security Hub documentation](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html) — standards, including the CIS AWS Foundations Benchmark.
- [AWS GuardDuty documentation](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [Configure the instance metadata service (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Security Reference Architecture (SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
