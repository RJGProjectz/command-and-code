---
title: AWS Troubleshooting
platforms: [AWS]
languages: [Bash]
tasks: [Troubleshooting, Administration]
category: Troubleshooting
tags: [aws, troubleshooting, accessdenied, decode authorization message, service quotas, ssm agent, reachability, throttling]
aliases: [aws accessdenied explicit deny, decode-authorization-message, aws expiredtoken, ec2 instance not in ssm, cannot ssh to ec2, aws throttlingexception, aws service quota]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# AWS Troubleshooting

AWS errors usually fall into five groups: **wrong identity or expired session**, **a policy denies it**, **limits** (quotas, throttling), **network path**, and **inside the guest**. Read the error code first; it names the group.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. AccessDenied and authentication errors

| Error | Meaning | Check |
| :--- | :--- | :--- |
| `ExpiredToken` / `ExpiredTokenException` | Session or SSO token expired | `aws sso login --profile <p>`; clear stale `AWS_*` environment variables |
| `InvalidClientTokenId` | The access key does not exist (deleted or wrong partition) | `aws configure list` to see which key is in use |
| `SignatureDoesNotMatch` | Wrong secret key, or clock skew | Sync the system clock |
| `AccessDenied ... with an explicit deny in a service control policy` | An SCP blocks it | [SCPs](policy-governance.md#1-inspect-what-is-attached); the management account must change it |
| `... explicit deny in a resource-based policy` / `permissions boundary` / `session policy` | The named layer denies it | Read that policy |
| `... because no identity-based policy allows the action` | Nothing allows it | Add the permission, or use another role |
| `UnauthorizedOperation` + `Encoded authorization failure message` (EC2) | Details are encoded | Decode (below) |

```bash
aws sts get-caller-identity                     # always first: who am I really?
aws configure list                              # where did the credentials come from?
aws sts decode-authorization-message --encoded-message <blob> --query DecodedMessage --output text | jq .
```

Decoding requires `sts:DecodeAuthorizationMessage`. The decoded JSON names the action, resource, and every matched statement.

## 2. Is a policy the cause?

```bash
aws iam simulate-principal-policy --policy-source-arn <role-arn> --action-names <service:Action> --resource-arns <arn> \
  --query "EvaluationResults[].{action:EvalActionName, decision:EvalDecision, matched:MatchedStatements[].SourcePolicyId}" --output table
```

Also check: the **resource policy** (bucket, key, secret, queue), the **KMS key policy** for encrypted resources (an S3 `AccessDenied` is often really a KMS denial), **VPC endpoint policies**, and **conditions** such as `aws:SourceIp`, which fails when calls come through a VPC endpoint.

## 3. Cannot reach an instance

1. Running and passing status checks? `aws ec2 describe-instance-status --instance-ids <id> --include-all-instances`
2. Is the path open? Run **Reachability Analyzer** ([Networking](networking.md#4-test-a-path-reachability-analyzer)).
3. Security group allows the source? Network ACL allows **both directions** including ephemeral ports?
4. Route table: public subnet has `0.0.0.0/0 → igw-...`; private subnet goes through a NAT gateway.
5. Public IP or Elastic IP present? Is DNS resolving to the right address?
6. Inside the guest: firewall, sshd/RDP service, full disk. Use the **console output**, **screenshot** or **serial console** ([Compute](compute.md#7-console-access-when-the-network-is-broken)).

Skip SSH altogether: `aws ssm start-session --target <id>`.

## 4. Instance missing from Systems Manager

```bash
aws ssm describe-instance-information --filters Key=InstanceIds,Values=<id>
```

Needs all of the following: the SSM Agent running; an instance profile with `AmazonSSMManagedInstanceCore` (or Default Host Management Configuration); outbound HTTPS to `ssm`, `ssmmessages` and `ec2messages` endpoints (or VPC interface endpoints for all three); and IMDS reachable. On the host: `sudo systemctl status amazon-ssm-agent` and `/var/log/amazon/ssm/amazon-ssm-agent.log` (Windows: `C:\ProgramData\Amazon\SSM\Logs\`).

## 5. Limits and throttling

| Error | Cause | Fix |
| :--- | :--- | :--- |
| `Throttling` / `ThrottlingException` / `RequestLimitExceeded` | API rate exceeded | Retry with backoff (`AWS_RETRY_MODE=adaptive`, `AWS_MAX_ATTEMPTS=10`) |
| `VcpuLimitExceeded`, `InstanceLimitExceeded` | Service quota | `aws service-quotas list-service-quotas --service-code ec2`; request an increase |
| `InsufficientInstanceCapacity` | AWS has no capacity of that type in that AZ | Another AZ or instance type |
| `LimitExceeded` (IAM) | For example 10 managed policies per role, or policy size | Merge policies, use permission sets |

```bash
aws service-quotas get-service-quota --service-code ec2 --quota-code L-1216C47A     # running On-Demand standard vCPUs
aws service-quotas request-service-quota-increase --service-code ec2 --quota-code L-1216C47A --desired-value 256   # change
```

## 6. CLI problems

```bash
aws --version                                   # v1 vs v2 differences break scripts
aws <command> --debug 2>&1 | less               # full request, endpoint, credential source and response
aws configure get region                        # many "not found" errors are the wrong region
export AWS_PAGER=""                              # stop the CLI paging output in scripts
```

Corporate TLS inspection causes `SSL: CERTIFICATE_VERIFY_FAILED`; set `AWS_CA_BUNDLE` to a bundle that includes the proxy CA rather than using `--no-verify-ssl`.

## 7. Where to look next

- **CloudTrail** `errorCode` and `errorMessage` for the failed call ([Audit logging](audit-logging.md#1-quick-lookups-event-history)).
- **AWS Health Dashboard** (`aws health describe-events`, Business support or higher) for service events.
- **CloudFormation** stack events for failed deployments: `aws cloudformation describe-stack-events --stack-name <s>`.

## Related

- [Linux troubleshooting](../linux/troubleshooting.md) · [Windows troubleshooting](../windows/troubleshooting.md) inside the guest
- [CLI & authentication](cli-authentication.md)
- [Azure troubleshooting](../azure/troubleshooting.md)

## Sources

- [Troubleshoot IAM access denied errors](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)
- [Troubleshooting SSM Agent](https://docs.aws.amazon.com/systems-manager/latest/userguide/troubleshooting-ssm-agent.html)
- [AWS CLI retries](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-retries.html)
