---
title: Amazon EC2 & Systems Manager (Compute)
platforms: [AWS]
languages: [Bash, PowerShell]
tasks: [Administration, Investigation, Incident Response]
category: Compute
tags: [aws, ec2, ssm, systems manager, run command, session manager, user data, instance profile, imdsv2, lambda]
aliases: [aws ec2 list instances, aws ssm send-command, ssm session manager, ec2 user data persistence, enforce imdsv2, ec2 serial console]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Amazon EC2 & Systems Manager (Compute)

EC2 instances are ordinary Windows and Linux hosts; inside the guest, use the [Windows](../windows/index.md) and [Linux](../linux/index.md) sections. This page covers the **control plane**: inventory, running code through **Systems Manager (SSM)**, user data, instance profiles and metadata.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. Inventory

```bash
aws ec2 describe-instances --query "Reservations[].Instances[].{id:InstanceId, state:State.Name, type:InstanceType, privateIp:PrivateIpAddress, publicIp:PublicIpAddress, profile:IamInstanceProfile.Arn, imds:MetadataOptions.HttpTokens, name:Tags[?Key=='Name']|[0].Value}" --output table
aws ec2 describe-instances --filters Name=instance-state-name,Values=running --query "length(Reservations[].Instances[])"
aws ssm describe-instance-information --query "InstanceInformationList[].{id:InstanceId, ping:PingStatus, os:PlatformName, agent:AgentVersion}" --output table
```

Regional: add `--region` or loop over regions ([Inventory](resource-hierarchy.md#3-which-regions-are-in-use)).

## 2. Power operations (change)

```bash
aws ec2 stop-instances --instance-ids i-0123456789abcdef0        # memory is lost; instance-store data is lost
aws ec2 start-instances --instance-ids i-0123456789abcdef0
aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 --disable-api-termination   # termination protection
```

For incident response, isolate and snapshot first ([Incident response](incident-response.md)).

## 3. Systems Manager: code execution from the control plane

SSM Run Command and Session Manager run as **SYSTEM** / **root** through the SSM Agent. Like Azure Run Command, this is a key admin tool and an attacker technique ([T1651](https://attack.mitre.org/techniques/T1651/)).

```bash
# change: executes code on the instance
cmd=$(aws ssm send-command --instance-ids i-0123456789abcdef0 --document-name AWS-RunShellScript \
  --parameters 'commands=["ss -tulpn","who","ps aux --sort=-%cpu | head"]' --query Command.CommandId --output text)
aws ssm get-command-invocation --command-id "$cmd" --instance-id i-0123456789abcdef0 --query StandardOutputContent --output text

# Windows
aws ssm send-command --instance-ids i-0123456789abcdef0 --document-name AWS-RunPowerShellScript \
  --parameters 'commands=["Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"]'

# Interactive shell without SSH, inbound ports or keys
aws ssm start-session --target i-0123456789abcdef0
```

Audit history: `aws ssm list-commands --query "Commands[].{id:CommandId, doc:DocumentName, by:RequestedDateTime, status:Status}"` and CloudTrail `SendCommand` / `StartSession` events. Send Session Manager transcripts to S3 or CloudWatch Logs in the SSM preferences.

## 4. User data

User data runs at first boot (cloud-init / EC2Launch), and on every boot if configured. Changing it while the instance is stopped is a persistence technique.

```bash
aws ec2 describe-instance-attribute --instance-id i-0123456789abcdef0 --attribute userData \
  --query UserData.Value --output text | base64 -d
```

CloudTrail event: `ModifyInstanceAttribute` with `userData` in the request parameters.

## 5. Enforce IMDSv2

```bash
# Instances still allowing IMDSv1
aws ec2 describe-instances --query "Reservations[].Instances[?MetadataOptions.HttpTokens=='optional'].InstanceId" --output text

# change: require tokens on one instance, and as the account default for new ones
aws ec2 modify-instance-metadata-options --instance-id i-0123456789abcdef0 --http-tokens required --http-put-response-hop-limit 1
aws ec2 modify-instance-metadata-defaults --http-tokens required --region ca-central-1
```

A hop limit of 1 stops containers on the host from reaching the instance's credentials. Use 2 only where pods need IMDS.

## 6. Instance profiles

```bash
aws ec2 describe-iam-instance-profile-associations --query "IamInstanceProfileAssociations[].{id:InstanceId, profile:IamInstanceProfile.Arn, state:State}" --output table
aws iam get-instance-profile --instance-profile-name <name> --query "InstanceProfile.Roles[].RoleName"
```

Anyone who runs code on the instance holds that role, so review what the role can do ([IAM](identity-access.md#3-who-is-an-administrator)).

## 7. Console access when the network is broken

| Tool | Command |
| :--- | :--- |
| Console output (boot log) | `aws ec2 get-console-output --instance-id <id> --latest --output text` |
| Screenshot | `aws ec2 get-console-screenshot --instance-id <id> --query ImageData --output text \| base64 -d > shot.jpg` |
| EC2 Serial Console | Enable once per account: `aws ec2 enable-serial-console-access` (**change**), then connect from the console |
| EC2 Instance Connect | `aws ec2-instance-connect ssh --instance-id <id>` (pushes a 60-second key) |

## 8. Lambda and containers at a glance

```bash
aws lambda list-functions --query "Functions[].{name:FunctionName, runtime:Runtime, role:Role, modified:LastModified}" --output table
aws lambda get-function-url-config --function-name <fn>          # public function URLs
aws ecs list-clusters && aws ecs list-services --cluster <cluster>
```

## Related

- [Networking](networking.md)
- [Incident response](incident-response.md)
- [Persistence & threat hunting](persistence-hunting.md)

## Sources

- [AWS Systems Manager Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html)
- [Instance metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html)
- [EC2 Serial Console](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html)
