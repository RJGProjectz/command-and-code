---
title: AWS CloudTrail (Audit Logging)
platforms: [AWS]
languages: [Bash, Python]
tasks: [Investigation, Incident Response, Forensics, Hardening]
category: Logging
tags: [aws, cloudtrail, organization trail, data events, cloudtrail lake, event history, log integrity, audit]
aliases: [aws cloudtrail lookup events, who deleted ec2 instance, cloudtrail organization trail, cloudtrail data events s3, cloudtrail lake sql, stoplogging cloudtrail]
difficulty: intermediate
verified: false
---

# AWS CloudTrail (Audit Logging)

CloudTrail records API calls. Know which part answers your question:

| Feature | Answers | Retention |
| :--- | :--- | :--- |
| **Event history** | Management events (create/modify/delete) in one account and region | 90 days, free, always on |
| **Trail** | Management (and optionally data) events delivered to S3 / CloudWatch Logs | As long as you keep the S3 objects |
| **Organization trail** | The same, for every account in the organization, from the management account | Same |
| **Data events** | Object-level and function-level calls (S3 `GetObject`, Lambda `Invoke`, DynamoDB items) | Off unless enabled; paid |
| **CloudTrail Lake** | SQL over events, across accounts and regions | 1–10 years per event data store |

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from AWS documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Quick lookups (event history)

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances \
  --start-time 2026-10-01T00:00:00Z --query "Events[].{time:EventTime, user:Username, event:EventName}" --output table

aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user-or-role-session> --max-results 50
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-0123456789abcdef0
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
```

Event history is **per region**. Global services (IAM, STS for the global endpoint, Organizations) log to `us-east-1`.

## 2. Trails and data events

```bash
aws cloudtrail describe-trails --query "trailList[].{name:Name, multiRegion:IsMultiRegionTrail, org:IsOrganizationTrail, bucket:S3BucketName, validation:LogFileValidationEnabled, kms:KmsKeyId}" --output table
aws cloudtrail get-trail-status --name <trail> --query "{logging:IsLogging, lastDelivery:LatestDeliveryTime, lastError:LatestDeliveryError}"
aws cloudtrail get-event-selectors --trail-name <trail>
```

Baseline: one **multi-region organization trail** with **log file validation**, SSE-KMS, delivered to a bucket in a separate **log archive account** with Object Lock.

```bash
# change: add S3 data events for one sensitive bucket (advanced event selectors)
aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[
 {"Name":"Management","FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]},
 {"Name":"S3 data - finance bucket","FieldSelectors":[
   {"Field":"eventCategory","Equals":["Data"]},
   {"Field":"resources.type","Equals":["AWS::S3::Object"]},
   {"Field":"resources.ARN","StartsWith":["arn:aws:s3:::finance-bucket/"]}]}]'
```

## 3. Reading an event

| Field | Use |
| :--- | :--- |
| `userIdentity.type` | `IAMUser`, `AssumedRole`, `Root`, `AWSService`, `FederatedUser` |
| `userIdentity.arn` | For roles: `arn:aws:sts::<acct>:assumed-role/<role>/<session-name>` |
| `userIdentity.accessKeyId` | `AKIA...` = long-term key; `ASIA...` = temporary credentials |
| `sourceIPAddress` | Caller IP, or an AWS service name for service-made calls |
| `userAgent` | CLI/SDK version, console, or tools such as Pacu / ScoutSuite |
| `errorCode` | `AccessDenied`, `UnauthorizedOperation`: bursts mean enumeration |
| `sharedEventID` / `requestID` | Correlate cross-account `AssumeRole` events |

Trace an assumed-role session back to a human: find the `AssumeRole` (or `AssumeRoleWithSAML` / Identity Center `Federate`) event whose `responseElements.credentials.accessKeyId` matches the `ASIA...` key.

## 4. CloudTrail Lake queries

```sql
-- Everything one access key did
SELECT eventTime, eventSource, eventName, awsRegion, sourceIPAddress, errorCode
FROM <event-data-store-id>
WHERE userIdentity.accessKeyId = 'AKIA...' AND eventTime > date_add('day', -30, now())
ORDER BY eventTime
```

```sql
-- AccessDenied bursts (enumeration) by principal and IP
SELECT userIdentity.arn, sourceIPAddress, count(*) AS denied, count(DISTINCT eventName) AS apis
FROM <event-data-store-id>
WHERE errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation') AND eventTime > date_add('hour', -24, now())
GROUP BY userIdentity.arn, sourceIPAddress
HAVING count(*) > 50
ORDER BY denied DESC
```

```sql
-- Console logins without MFA
SELECT eventTime, userIdentity.arn, sourceIPAddress
FROM <event-data-store-id>
WHERE eventName = 'ConsoleLogin' AND element_at(additionalEventData, 'MFAUsed') = 'No'
```

```bash
aws cloudtrail start-query --query-statement "SELECT eventName, count(*) FROM <eds-id> WHERE eventTime > '2026-10-10 00:00:00' GROUP BY eventName"
aws cloudtrail get-query-results --query-id <id>
```

## 5. Log tampering

Alert on `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` (narrowing selectors), `DeleteEventDataStore`, and `PutBucketPolicy` / `PutBucketLifecycle` on the log bucket ([T1562.008](https://attack.mitre.org/techniques/T1562/008/)). An SCP that denies these actions to everyone except a break-glass role is the strongest control ([Policy & governance](policy-governance.md#2-service-control-policies)).

Validate that delivered log files were not modified:

```bash
aws cloudtrail validate-logs --trail-arn <trail-arn> --start-time 2026-10-01T00:00:00Z
```

## 6. Python: pull events for a case

```python
import boto3, json
ct = boto3.client("cloudtrail", region_name="us-east-1")
pages = ct.get_paginator("lookup_events").paginate(
    LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "suspect-user"}])
with open("ct-suspect-user.jsonl", "w") as out:
    for page in pages:
        for e in page["Events"]:
            out.write(e["CloudTrailEvent"] + "\n")
```

Hash the export (`sha256sum`) and record the query, account, region and time range with the evidence.

## Related

- [Monitoring & log queries](monitoring-logs.md) (Athena over the trail bucket)
- [Persistence & threat hunting](persistence-hunting.md)
- [Incident response](incident-response.md)

## Sources

- [CloudTrail concepts](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html)
- [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [CloudTrail Lake queries](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-create-edit-query.html)
