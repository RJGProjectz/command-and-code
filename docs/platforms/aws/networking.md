---
title: AWS Networking (VPC, Security Groups, Flow Logs)
platforms: [AWS]
languages: [Bash]
tasks: [Administration, Troubleshooting, Investigation, Hardening]
category: Networking
tags: [aws, vpc, security groups, nacl, vpc flow logs, reachability analyzer, network firewall, route tables, endpoints]
aliases: [aws security group open to world, aws 0.0.0.0/0 port 22, aws vpc flow logs query, aws reachability analyzer, aws nacl vs security group, aws network firewall logs]
difficulty: intermediate
verified: false
---

# AWS Networking (VPC, Security Groups, Flow Logs)

Traffic to an EC2 instance passes the subnet's **network ACL** (stateless, ordered rules, allow and deny) and the ENI's **security groups** (stateful, allow-only, all rules combined). Routing comes from the subnet's **route table**: internet gateway, NAT gateway, Transit Gateway, VPC endpoint or AWS Network Firewall.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from AWS documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Inventory

```bash
aws ec2 describe-vpcs --query "Vpcs[].{id:VpcId, cidr:CidrBlock, default:IsDefault, name:Tags[?Key=='Name']|[0].Value}" --output table
aws ec2 describe-subnets --query "Subnets[].{id:SubnetId, vpc:VpcId, cidr:CidrBlock, az:AvailabilityZone, publicIpOnLaunch:MapPublicIpOnLaunch}" --output table
aws ec2 describe-route-tables --query "RouteTables[].{id:RouteTableId, routes:Routes[].[DestinationCidrBlock, GatewayId, NatGatewayId, TransitGatewayId]}" --output json
aws ec2 describe-internet-gateways --output table
aws ec2 describe-vpc-peering-connections --output table
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[].{id:VpcEndpointId, svc:ServiceName, type:VpcEndpointType}" --output table
aws ec2 describe-addresses --output table                    # Elastic IPs
```

Default VPCs exist in every region and have public subnets. Delete them where unused.

## 2. Security groups open to the internet

```bash
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query "SecurityGroups[].{id:GroupId, name:GroupName, rules:IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']].[IpProtocol, FromPort, ToPort]}" --output json

# Management ports from anywhere (IPv4 and IPv6)
for p in 22 3389 5985 5986; do
  aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=$p Name=ip-permission.cidr,Values=0.0.0.0/0 \
    --query "SecurityGroups[].[GroupId, GroupName]" --output text
  aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=$p Name=ip-permission.ipv6-cidr,Values=::/0 \
    --query "SecurityGroups[].[GroupId, GroupName]" --output text
done

# Which ENIs use a group
aws ec2 describe-network-interfaces --filters Name=group-id,Values=sg-0123456789abcdef0 \
  --query "NetworkInterfaces[].{eni:NetworkInterfaceId, instance:Attachment.InstanceId, ip:PrivateIpAddress}" --output table
```

Rules with port range `-1` or `0-65535` and protocol `-1` (all) are worse than they look.

## 3. Network ACLs

```bash
aws ec2 describe-network-acls --query "NetworkAcls[].{id:NetworkAclId, vpc:VpcId, entries:Entries[].[RuleNumber, Egress, RuleAction, CidrBlock, PortRange.From, PortRange.To]}" --output json
```

NACLs are stateless: allow the **ephemeral return ports** (1024–65535) or replies are dropped.

## 4. Test a path: Reachability Analyzer

```bash
path=$(aws ec2 create-network-insights-path --source i-0aaa... --destination i-0bbb... --protocol tcp --destination-port 443 \
  --query NetworkInsightsPath.NetworkInsightsPathId --output text)
run=$(aws ec2 start-network-insights-analysis --network-insights-path-id "$path" --query NetworkInsightsAnalysis.NetworkInsightsAnalysisId --output text)
aws ec2 describe-network-insights-analyses --network-insights-analysis-ids "$run" \
  --query "NetworkInsightsAnalyses[].{reachable:NetworkPathFound, explanations:Explanations[].ExplanationCode}"
```

It names the security group, NACL or route that blocks the path, without sending a packet. **Network Access Analyzer** answers the inverse question: "what can reach this from the internet?".

## 5. VPC Flow Logs

```bash
aws ec2 describe-flow-logs --output table
# change: all traffic for a VPC to CloudWatch Logs
aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-0123456789abcdef0 --traffic-type ALL \
  --log-destination-type cloud-watch-logs --log-group-name /vpc/flowlogs --deliver-logs-permission-arn <role-arn>
```

Default record: `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status`.

```sql
-- CloudWatch Logs Insights: top talkers to the internet from one host
fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter srcAddr = "10.0.1.25" and action = "ACCEPT"
| stats sum(bytes) as totalBytes by dstAddr, dstPort
| sort totalBytes desc
| limit 25
```

```sql
-- Rejected inbound attempts by source (scanning)
fields srcAddr, dstPort
| filter action = "REJECT"
| stats count(*) as attempts by srcAddr
| sort attempts desc
| limit 20
```

For long retention, send flow logs to S3 and query with Athena ([Monitoring & log queries](monitoring-logs.md#4-athena-over-s3-logs)).

## 6. Block or isolate (change)

```bash
# Remove an internet-wide SSH rule
aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 22 --cidr 0.0.0.0/0

# Deny one address at the subnet edge (NACLs can deny; security groups cannot)
aws ec2 create-network-acl-entry --network-acl-id acl-0123... --ingress --rule-number 50 --protocol -1 \
  --cidr-block 203.0.113.10/32 --rule-action deny
```

To isolate a whole instance, use the quarantine security group in [Incident response](incident-response.md#2-isolate-an-instance).

## 7. Private access to AWS services

Gateway endpoints (S3, DynamoDB) and interface endpoints (PrivateLink) keep traffic off the internet. An **endpoint policy** can restrict them to your own buckets, which blocks exfiltration to an attacker's bucket over the same endpoint.

## Related

- [Linux networking](../linux/networking.md) · [Windows networking](../windows/networking.md) inside the guest
- [Troubleshooting → cannot reach an instance](troubleshooting.md#3-cannot-reach-an-instance)
- [Network flood detection](../../detection/sigma/dos-flood.md)

## Sources

- [Security groups vs network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/infrastructure-security.html)
- [VPC Flow Logs records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [Reachability Analyzer](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)
