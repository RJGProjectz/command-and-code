---
title: Amazon S3 & Data Exposure
platforms: [AWS]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Storage
tags: [aws, s3, bucket policy, block public access, acl, presigned url, object lock, versioning, ebs snapshots]
aliases: [public s3 bucket, s3 block public access, s3 bucket policy audit, who downloaded from s3, s3 object lock ransomware, public ebs snapshot]
difficulty: intermediate
verified: false
---

# Amazon S3 & Data Exposure

S3 access is the union of **bucket policies**, **IAM policies**, **access points** and (legacy) **ACLs**, capped by **Block Public Access (BPA)** at account and bucket level. Since April 2023, new buckets have BPA on and ACLs disabled, but older buckets keep whatever they had.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from AWS documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Account-level Block Public Access

```bash
aws s3control get-public-access-block --account-id 111122223333
# change: block all public access for every bucket in the account
aws s3control put-public-access-block --account-id 111122223333 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

## 2. Find exposed buckets

```bash
for b in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
  bpa=$(aws s3api get-public-access-block --bucket "$b" --query "PublicAccessBlockConfiguration" --output text 2>/dev/null || echo "NONE")
  status=$(aws s3api get-bucket-policy-status --bucket "$b" --query "PolicyStatus.IsPublic" --output text 2>/dev/null || echo "no-policy")
  echo -e "$b\tBPA=$bpa\tpublicPolicy=$status"
done
```

IAM Access Analyzer reports buckets shared publicly **or with other accounts** in one list ([IAM](identity-access.md#5-iam-access-analyzer)). Test from outside without credentials:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<bucket>.s3.amazonaws.com/?list-type=2"     # 200 = publicly listable
```

## 3. Read the bucket's policy and settings

```bash
aws s3api get-bucket-policy --bucket <bucket> --query Policy --output text | jq .
aws s3api get-bucket-ownership-controls --bucket <bucket>      # BucketOwnerEnforced = ACLs disabled
aws s3api get-bucket-acl --bucket <bucket>
aws s3api get-bucket-encryption --bucket <bucket>
aws s3api get-bucket-versioning --bucket <bucket>
aws s3api get-bucket-logging --bucket <bucket>
aws s3control list-access-points --account-id 111122223333
```

Red flags in a policy: `"Principal": "*"` without a `Condition` limiting `aws:SourceVpce`, `aws:PrincipalOrgID` or `aws:SourceIp`; and `s3:PutBucketPolicy` or `s3:*` granted to other accounts.

## 4. Presigned URLs

A presigned URL carries the signer's permissions until it expires (up to 7 days for IAM user keys; no longer than the session for temporary credentials). You cannot list or revoke individual URLs. To kill them, revoke the signer's credentials, or deny requests signed before a time:

```json
{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"],
 "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2026-10-12T06:00:00Z"}}}
```

## 5. Who read or wrote objects?

Object reads are **data events**: not in CloudTrail by default. Enable them on sensitive buckets ([Audit logging](audit-logging.md#2-trails-and-data-events)), or turn on **server access logging**.

```sql
-- CloudTrail Lake: who downloaded from a bucket in the last day
SELECT eventTime, userIdentity.arn, sourceIPAddress, element_at(requestParameters, 'key') AS objectKey
FROM <event-data-store-id>
WHERE eventSource = 's3.amazonaws.com' AND eventName = 'GetObject'
  AND element_at(requestParameters, 'bucketName') = '<bucket>'
  AND eventTime > date_add('day', -1, now())
ORDER BY eventTime DESC
```

Control-plane red flags in CloudTrail management events: `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock`, `PutBucketReplication` (copying data to another account), `PutBucketLifecycle` with short expiry (data destruction).

## 6. Ransomware and deletion protection

```bash
aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled     # change
aws s3api get-object-lock-configuration --bucket <bucket>
```

- **Versioning** keeps overwritten and deleted objects as prior versions.
- **Object Lock** in *compliance* mode makes versions undeletable by anyone, including root, until retention ends. Use it for backups and log archives.
- **MFA Delete** (root only) requires MFA to delete versions or change versioning.

## 7. EBS snapshots and AMIs

Public or shared snapshots leak whole disks.

```bash
aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --query "Snapshots[].SnapshotId"   # public
aws ec2 get-snapshot-block-public-access-state
aws ec2 enable-snapshot-block-public-access --state block-all-sharing      # change
aws ec2 describe-images --owners self --filters Name=is-public,Values=true --query "Images[].ImageId"
```

## 8. Copy data for analysis

```bash
aws s3 sync s3://<bucket>/<prefix> ./evidence/<case-id>/ --exact-timestamps
aws s3api list-object-versions --bucket <bucket> --prefix <key>     # recover pre-ransomware versions
```

## Related

- [Keys & secrets](keys-secrets.md) (SSE-KMS)
- [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md)
- [Backup and recovery](../../tasks/administration/backup-and-recovery.md)

## Sources

- [Blocking public access to S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Logging S3 data events with CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html)
