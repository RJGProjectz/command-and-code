---
title: AWS SCPs, Config Rules & Governance
platforms: [AWS]
languages: [Bash]
tasks: [Hardening, Assurance, Administration, Governance]
category: Governance
tags: [aws, service control policies, scp, resource control policies, aws config, conformance packs, control tower, tag policies]
aliases: [aws scp examples, deny region scp, protect cloudtrail scp, aws config rules noncompliant, aws control tower guardrails, resource control policy]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# AWS SCPs, Config Rules & Governance

Governance in AWS has two halves:

- **Preventive**: **service control policies (SCPs)** set the maximum permissions for principals in member accounts. **Resource control policies (RCPs)** set the maximum permissions on resources such as S3, KMS and Secrets Manager. Neither grants anything.
- **Detective**: **AWS Config rules** and **conformance packs** evaluate resource configuration continuously, and Security Hub controls build on them ([Security posture](security-posture.md)).

**AWS Control Tower** packages both as "controls" on top of a multi-account landing zone.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**. A wrong SCP on the root can lock every account out of a service. Attach to a test OU first.

## 1. Inspect what is attached

```bash
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output table
aws organizations list-policies --filter RESOURCE_CONTROL_POLICY --output table
aws organizations list-policies-for-target --target-id <ou-or-account-id> --filter SERVICE_CONTROL_POLICY --output table
aws organizations describe-policy --policy-id p-xxxxxxxx --query Policy.Content --output text | jq .
aws organizations list-targets-for-policy --policy-id p-xxxxxxxx --output table
```

SCPs do **not** affect the management account, and do not restrict service-linked roles.

## 2. Service control policies

Protect the security tooling from anyone in member accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ProtectSecurityServices",
    "Effect": "Deny",
    "Action": [
      "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
      "guardduty:DeleteDetector", "guardduty:DisassociateFromAdministratorAccount", "guardduty:UpdateDetector",
      "securityhub:DisableSecurityHub", "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
      "access-analyzer:DeleteAnalyzer", "organizations:LeaveOrganization"
    ],
    "Resource": "*",
    "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass-SecurityAdmin"}}
  }]
}
```

Other common SCPs: deny creating IAM users and access keys; deny `ec2:RunInstances` without IMDSv2 (`ec2:MetadataHttpTokens` ≠ `required`); deny disabling EBS default encryption and S3 Block Public Access; deny root user actions in member accounts.

## 3. Region deny

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnapprovedRegions",
    "Effect": "Deny",
    "NotAction": ["iam:*", "organizations:*", "sts:*", "support:*", "cloudfront:*", "route53:*", "waf:*",
                  "budgets:*", "ce:*", "health:*", "kms:*", "account:*", "sso:*", "trustedadvisor:*"],
    "Resource": "*",
    "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["ca-central-1", "us-east-1"]}}
  }]
}
```

Global services must be excluded with `NotAction`, or they break. Check the current AWS example before you deploy it.

```bash
# change
aws organizations create-policy --name deny-regions --type SERVICE_CONTROL_POLICY --content file://deny-regions.json --description "Allow ca-central-1 and us-east-1 only"
aws organizations attach-policy --policy-id p-xxxxxxxx --target-id ou-test-xxxxxxxx
```

## 4. Resource control policies

RCPs apply to resources regardless of who calls them. A typical use is a **data perimeter**: only principals in your organization may access your S3 buckets, KMS keys and secrets.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EnforceOrgIdentities",
    "Effect": "Deny",
    "Principal": "*",
    "Action": ["s3:*", "kms:*", "secretsmanager:*", "sts:AssumeRole"],
    "Resource": "*",
    "Condition": {
      "StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"},
      "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}
    }
  }]
}
```

Test against legitimate third-party access (vendors, CloudFront, log delivery) before attaching.

## 5. AWS Config rules

```bash
aws configservice describe-configuration-recorder-status --query "ConfigurationRecordersStatus[].{name:name, recording:recording, lastStatus:lastStatus}"
aws configservice describe-config-rules --query "ConfigRules[].ConfigRuleName" --output text
aws configservice describe-compliance-by-config-rule --compliance-types NON_COMPLIANT --output table
aws configservice get-compliance-details-by-config-rule --config-rule-name <rule> --compliance-types NON_COMPLIANT \
  --query "EvaluationResults[].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId" --output text
aws configservice describe-aggregate-compliance-by-config-rules --configuration-aggregator-name org-aggregator \
  --filters ComplianceType=NON_COMPLIANT --output table
```

Deploy rules as **conformance packs** (for example *Operational Best Practices for CIS*) from the delegated admin account, so every account gets the same set.

```bash
# change: add a managed rule
aws configservice put-config-rule --config-rule '{"ConfigRuleName":"s3-bucket-public-read-prohibited","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_PUBLIC_READ_PROHIBITED"}}'
```

Auto-remediation runs an SSM Automation document on non-compliant resources. Start with notifications only.

## 6. Tag and backup policies

**Tag policies** standardize tag keys and values. **Backup policies** enforce AWS Backup plans across accounts. Both live in Organizations next to SCPs:

```bash
aws organizations list-policies --filter TAG_POLICY
aws organizations list-policies --filter BACKUP_POLICY
```

## 7. Watch for drift

Alert on `DetachPolicy`, `DeletePolicy`, `UpdatePolicy` and `DisablePolicyType` in Organizations, and on `DeleteConfigRule` / `StopConfigurationRecorder` in member accounts ([CloudTrail](audit-logging.md#5-log-tampering)). Keep SCPs, RCPs and Config rules as code (Terraform, CloudFormation StackSets, Control Tower customizations) with reviewed changes.

## Related

- [Organizations & inventory](resource-hierarchy.md)
- [Security posture](security-posture.md)
- [Concept: GRC](../../fundamentals/grc/regulatory-frameworks.md)

## Sources

- [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [AWS Config conformance packs](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html)
