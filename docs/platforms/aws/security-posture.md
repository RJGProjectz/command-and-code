---
title: AWS Security Hub, GuardDuty & Inspector (Posture & Alerts)
platforms: [AWS]
languages: [Bash]
tasks: [Assurance, Hardening, Investigation, Incident Response]
category: Posture
tags: [aws, security hub, guardduty, inspector, findings, cspm, foundational security best practices, detective]
aliases: [guardduty findings cli, security hub failed controls, aws cspm, guardduty finding types, inspector vulnerabilities, aws security posture]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# AWS Security Hub, GuardDuty & Inspector (Posture & Alerts)

| Service | Job |
| :--- | :--- |
| **GuardDuty** | Threat detection from CloudTrail, VPC flow logs, DNS logs, EKS audit logs, S3 data events and runtime agents. Produces **findings**. |
| **Security Hub** | Posture (CSPM): runs controls such as AWS Foundational Security Best Practices (FSBP) and CIS, and aggregates findings from GuardDuty, Inspector, Macie and Access Analyzer in ASFF / OCSF. |
| **Inspector** | Vulnerability scanning of EC2, ECR images and Lambda. |
| **Detective** | Graph-based investigation of GuardDuty findings. |
| **Macie** | Sensitive-data discovery in S3. |

Enable all of them organization-wide from a **delegated administrator** account (usually the security tooling account), in **every enabled region**.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**. These services have per-volume costs.

## 1. Is it on everywhere?

```bash
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  gd=$(aws guardduty list-detectors --region "$r" --query "DetectorIds[0]" --output text)
  sh=$(aws securityhub describe-hub --region "$r" --query HubArn --output text 2>/dev/null || echo "off")
  echo -e "$r\tguardduty=$gd\tsecurityhub=$sh"
done
aws guardduty list-organization-admin-accounts
aws securityhub list-organization-admin-accounts
```

## 2. GuardDuty findings

```bash
det=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)
ids=$(aws guardduty list-findings --detector-id "$det" \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7},"service.archived":{"Eq":["false"]}}}' --query FindingIds --output text)
aws guardduty get-findings --detector-id "$det" --finding-ids $ids \
  --query "Findings[].{type:Type, sev:Severity, resource:Resource.ResourceType, account:AccountId, updated:UpdatedAt}" --output table
```

Finding types worth knowing:

| Type (prefix) | Meaning |
| :--- | :--- |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Instance-role credentials used from outside AWS |
| `CredentialAccess:IAMUser/AnomalousBehavior` | Unusual API calls to get secrets or credentials |
| `Discovery:IAMUser/AnomalousBehavior` | Enumeration by a principal that does not usually do it |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | Trail stopped or deleted |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | Instance talks to mining pools ([Cryptomining detection](../../detection/sigma/cryptomining.md)) |
| `Policy:S3/BucketBlockPublicAccessDisabled` | BPA removed from a bucket |
| `Execution:Runtime/NewBinaryExecuted` | Runtime Monitoring: new binary in a container or instance |

## 3. Security Hub posture

```bash
aws securityhub get-enabled-standards --query "StandardsSubscriptions[].StandardsArn" --output text
aws securityhub get-findings --filters '{"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}],"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query "Findings[].{control:Compliance.SecurityControlId, title:Title, resource:Resources[0].Id}" --max-items 50 --output table
```

High-value FSBP controls to fix first: `IAM.6` (root hardware MFA), `CloudTrail.1` (multi-region trail), `S3.1`/`S3.8` (Block Public Access), `EC2.8` (IMDSv2), `EC2.19` (unrestricted management ports), `GuardDuty.1`, `KMS.4` (rotation).

## 4. Inspector

```bash
aws inspector2 batch-get-account-status --account-ids 111122223333
aws inspector2 list-findings --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
  --query "findings[].{title:title, resource:resources[0].id, fixAvailable:fixAvailable, exploit:exploitAvailable}" --output table
```

Prioritize `exploitAvailable = YES` on internet-reachable resources ([Concept: vulnerability management](../../fundamentals/concepts/vulnerability-management.md)).

## 5. Route findings (change)

```bash
aws events put-rule --name guardduty-high --event-pattern '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"],"detail":{"severity":[{"numeric":[">=",7]}]}}'
aws events put-targets --rule guardduty-high --targets Id=sns,Arn=<sns-topic-arn>
```

Security Hub sends `Security Hub Findings - Imported` events the same way. Send both to your SIEM or ticketing system rather than relying on the console.

## 6. Triage a finding

1. Read `Resource`, `Service.Action` (API, network or DNS details) and `Service.Count` / first and last seen.
2. Pull the principal's activity from [CloudTrail](audit-logging.md#4-cloudtrail-lake-queries), or open the finding in Detective.
3. For an instance finding, isolate and snapshot it ([Incident response](incident-response.md)).
4. Archive the finding only with a written reason. Use **suppression rules** for known-benign patterns rather than archiving them one by one.

## Related

- [Policy & governance](policy-governance.md)
- [Monitoring & log queries](monitoring-logs.md)
- [Assurance tasks](../../tasks/assurance/index.md)

## Sources

- [GuardDuty finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Security Hub controls reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)
- [Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html)
