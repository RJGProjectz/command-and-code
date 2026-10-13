---
title: AWS Organizations, Accounts & Inventory
platforms: [AWS]
languages: [Bash, Python]
tasks: [Administration, Investigation, Assurance]
category: Inventory
tags: [aws, organizations, organizational units, accounts, resource explorer, aws config, tags, inventory, regions]
aliases: [list aws accounts, aws organization structure, aws resource explorer search, aws inventory all regions, what is running in this aws account, aws config advanced query]
difficulty: basic
verified: true
last_verified: 2026-10-12
---

# AWS Organizations, Accounts & Inventory

In AWS the **account** is the hard security boundary. **AWS Organizations** groups accounts into **organizational units (OUs)** under one **management account**, and **service control policies (SCPs)** applied to an OU limit every account below it. Most resources are also **regional**, so inventory means *every account × every region*.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Everything here is read-only except commands marked **change**.

## 1. The hierarchy

| Level | Example | Notes |
| :--- | :--- | :--- |
| Organization | `o-a1b2c3d4e5` | One management account. Keep workloads out of it. |
| Root | `r-ab12` | Policies here apply to every account. |
| Organizational unit | `Security`, `Workloads/Prod` | Nested up to five levels. Attach SCPs and RCPs here. |
| Account | `111122223333` | Billing, IAM and blast-radius boundary. |
| Region | `ca-central-1` | Most resources live in one region; IAM, Organizations, Route 53 and CloudFront are global. |

## 2. Walk the organization

Run from the management account or a delegated administrator.

```bash
aws organizations describe-organization
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id r-ab12
aws organizations list-accounts --query "Accounts[].{id:Id, name:Name, status:Status, email:Email}" --output table
aws organizations list-accounts-for-parent --parent-id ou-ab12-xxxxxxxx --output table
aws organizations list-delegated-administrators --output table
```

## 3. Which regions are in use?

```bash
aws ec2 describe-regions --all-regions --query "Regions[].{name:RegionName, status:OptInStatus}" --output table

# Count EC2 instances in every enabled region
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  printf "%-16s %s\n" "$r" "$(aws ec2 describe-instances --region "$r" --query 'length(Reservations[].Instances[])' --output text)"
done
```

Attackers favor regions nobody watches. Disable unused opt-in regions, or deny them with an SCP ([Policy & governance](policy-governance.md#3-region-deny)).

## 4. Search everything with Resource Explorer

Resource Explorer indexes resources across regions (and, with an aggregator, across accounts).

```bash
aws resource-explorer-2 list-indexes --output table
aws resource-explorer-2 search --query-string "resourcetype:ec2:instance" --max-results 100
aws resource-explorer-2 search --query-string "tag.key:owner -tag.value:*" --max-results 100   # missing owner value
aws resource-explorer-2 search --query-string "region:us-east-1 service:s3"
```

## 5. AWS Config: inventory with history

AWS Config records each resource's configuration and every change. With an **aggregator**, you can query all accounts and regions with SQL:

```bash
aws configservice select-aggregate-resource-config --configuration-aggregator-name org-aggregator \
  --expression "SELECT resourceType, COUNT(*) WHERE resourceType LIKE 'AWS::EC2::%' GROUP BY resourceType"

aws configservice select-resource-config --expression \
  "SELECT resourceId, resourceName, configuration.publicIp WHERE resourceType = 'AWS::EC2::Instance' AND configuration.state.name = 'running'"

# Change history for one resource
aws configservice get-resource-config-history --resource-type AWS::EC2::SecurityGroup --resource-id sg-0123456789abcdef0 --limit 10
```

Config history answers "what did this look like before?". [CloudTrail](audit-logging.md) answers "who changed it?".

## 6. Tags

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=environment,Values=prod \
  --query "ResourceTagMappingList[].ResourceARN" --output text
aws resourcegroupstaggingapi tag-resources --resource-arn-list <arn> --tags owner=secops     # change
```

Enforce tag keys and values with **tag policies** in Organizations.

## 7. Python: every account, every region

```python
import boto3

org = boto3.client("organizations")
accounts = [a for page in org.get_paginator("list_accounts").paginate() for a in page["Accounts"] if a["Status"] == "ACTIVE"]
regions = [r["RegionName"] for r in boto3.client("ec2").describe_regions()["Regions"]]

for acct in accounts:
    creds = boto3.client("sts").assume_role(
        RoleArn=f"arn:aws:iam::{acct['Id']}:role/OrganizationAccountAccessRole",
        RoleSessionName="inventory")["Credentials"]
    s = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                      aws_session_token=creds["SessionToken"])
    for region in regions:
        n = sum(len(r["Instances"]) for r in s.client("ec2", region_name=region).describe_instances()["Reservations"])
        if n:
            print(acct["Id"], region, n)
```

Use a read-only audit role (for example one with `SecurityAudit` / `ViewOnlyAccess`) instead of `OrganizationAccountAccessRole` for routine inventory.

## Related

- [Policy & governance](policy-governance.md)
- [Audit logging](audit-logging.md)
- [Security posture](security-posture.md)

## Sources

- [AWS Organizations terminology](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html)
- [AWS Resource Explorer search syntax](https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html)
- [AWS Config advanced queries](https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html)
