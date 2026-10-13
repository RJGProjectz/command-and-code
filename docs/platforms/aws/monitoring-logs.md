---
title: Amazon CloudWatch, Logs Insights & Athena
platforms: [AWS]
languages: [Bash, Python]
tasks: [Investigation, Troubleshooting, Detection Engineering, Administration]
category: Logging
tags: [aws, cloudwatch, logs insights, athena, metrics, alarms, eventbridge, cloudwatch agent]
aliases: [cloudwatch logs insights query, athena cloudtrail table, cloudwatch alarm cli, eventbridge rule security, cloudwatch agent install, query vpc flow logs athena]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Amazon CloudWatch, Logs Insights & Athena

AWS splits monitoring across three services:

- **CloudWatch Metrics and Alarms**: numbers and thresholds.
- **CloudWatch Logs**: log groups, queried with **Logs Insights**.
- **Amazon Athena**: SQL over logs stored in S3 (CloudTrail, VPC flow logs, ALB, S3 access logs). It is cheaper for long retention.

**EventBridge** routes API events (from CloudTrail) and findings to alerts and automation in near real time.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**. Athena bills per TB scanned; partition and filter.

## 1. Log groups

```bash
aws logs describe-log-groups --query "logGroups[].{name:logGroupName, retentionDays:retentionInDays, storedBytes:storedBytes}" --output table
aws logs put-retention-policy --log-group-name /vpc/flowlogs --retention-in-days 365     # change
aws logs tail /aws/lambda/<fn> --since 1h --follow
aws logs filter-log-events --log-group-name <group> --filter-pattern '"AccessDenied"' --start-time $(date -d '-1 hour' +%s000)
```

Log groups default to **never expire**. Set retention deliberately, both for cost and for evidence.

## 2. Logs Insights

```bash
qid=$(aws logs start-query --log-group-name /aws/cloudtrail/org --start-time $(date -d '-24 hours' +%s) --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, userIdentity.arn, sourceIPAddress | filter errorCode = "AccessDenied" | stats count(*) by userIdentity.arn | sort count(*) desc | limit 20' \
  --query queryId --output text)
aws logs get-query-results --query-id "$qid"
```

```sql
-- Linux auth failures shipped by the CloudWatch agent
fields @timestamp, @message
| filter @message like /Failed password/
| parse @message /from (?<ip>\d+\.\d+\.\d+\.\d+)/
| stats count(*) as failures by ip
| sort failures desc
```

## 3. CloudWatch agent (inside instances)

The unified CloudWatch agent ships OS logs and metrics. Its configuration is stored in SSM Parameter Store and pushed with the `AmazonCloudWatch-ManageAgent` document.

```bash
aws ssm send-command --document-name AmazonCloudWatch-ManageAgent --targets Key=tag:monitoring,Values=on \
  --parameters 'action=configure,mode=ec2,optionalConfigurationSource=ssm,optionalConfigurationLocation=AmazonCloudWatch-linux'   # change
```

Windows Security events and Linux `/var/log/secure` / `auth.log` should go to their own log groups with retention ≥ 1 year.

## 4. Athena over S3 logs

Create a CloudTrail table with **partition projection** so queries scan only the days you ask for:

```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
  eventVersion STRING, userIdentity STRUCT<type:STRING, principalId:STRING, arn:STRING, accountId:STRING,
    accessKeyId:STRING, userName:STRING, sessionContext:STRUCT<sessionIssuer:STRUCT<arn:STRING, userName:STRING>>>,
  eventTime STRING, eventSource STRING, eventName STRING, awsRegion STRING, sourceIPAddress STRING,
  userAgent STRING, errorCode STRING, errorMessage STRING, requestParameters STRING, responseElements STRING,
  requestId STRING, eventId STRING, readOnly STRING, recipientAccountId STRING, sharedEventId STRING)
PARTITIONED BY (account STRING, region STRING, day STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<trail-bucket>/AWSLogs/<org-id>/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.account.type'='enum', 'projection.account.values'='111122223333,444455556666',
  'projection.region.type'='enum', 'projection.region.values'='us-east-1,ca-central-1',
  'projection.day.type'='date', 'projection.day.range'='2025/01/01,NOW', 'projection.day.format'='yyyy/MM/dd',
  'projection.day.interval'='1', 'projection.day.interval.unit'='DAYS',
  'storage.location.template'='s3://<trail-bucket>/AWSLogs/<org-id>/${account}/CloudTrail/${region}/${day}');
```

```sql
-- IAM changes in the last week
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress, requestParameters
FROM cloudtrail_logs
WHERE day >= date_format(current_date - interval '7' day, '%Y/%m/%d')
  AND eventSource = 'iam.amazonaws.com' AND readOnly = 'false'
ORDER BY eventTime DESC
```

```bash
aws athena start-query-execution --query-string "SELECT count(*) FROM cloudtrail_logs WHERE day = '2026/10/11'" \
  --work-group primary --result-configuration OutputLocation=s3://<athena-results-bucket>/
```

## 5. Metrics and alarms (change)

```bash
aws cloudwatch list-metrics --namespace AWS/EC2 --dimensions Name=InstanceId,Value=i-0123456789abcdef0
aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name NetworkOut --dimensions Name=InstanceId,Value=i-0123... \
  --start-time $(date -u -d '-6 hours' +%FT%TZ) --end-time $(date -u +%FT%TZ) --period 300 --statistics Sum

aws cloudwatch put-metric-alarm --alarm-name cpu-high-i-0123 --namespace AWS/EC2 --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-0123... --statistic Average --period 300 --evaluation-periods 3 \
  --threshold 90 --comparison-operator GreaterThanThreshold --alarm-actions <sns-topic-arn>
```

## 6. EventBridge: real-time security alerts (change)

```bash
aws events put-rule --name ct-logging-tampering --event-pattern '{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {"eventName": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]}}'
aws events put-targets --rule ct-logging-tampering --targets Id=sns,Arn=<sns-topic-arn>
```

EventBridge rules are regional; deploy them in every enabled region (StackSets), and in `us-east-1` for global services.

## Related

- [Audit logging](audit-logging.md)
- [Security posture](security-posture.md) (GuardDuty findings to EventBridge)
- [SPL reference](../../detection/spl/index.md) if CloudTrail lands in Splunk

## Sources

- [CloudWatch Logs Insights query syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
- [Querying CloudTrail logs with Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [EventBridge events from AWS services](https://docs.aws.amazon.com/eventbridge/latest/ref/events.html)
