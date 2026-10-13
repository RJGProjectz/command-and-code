---
title: Google Cloud VPC & Firewall Rules
platforms: [GCP]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Networking
tags: [gcp, vpc, firewall rules, firewall policies, vpc flow logs, shared vpc, private google access, vpc service controls, cloud nat]
aliases: [gcloud compute firewall-rules list, gcp open firewall 0.0.0.0/0, gcp vpc flow logs query, gcp firewall rules logging, gcp shared vpc, vpc service controls perimeter]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Google Cloud VPC & Firewall Rules

A Google Cloud **VPC network is global**; subnets are regional. Traffic is filtered by **hierarchical firewall policies** (org/folder), then **network firewall policies**, then **VPC firewall rules**. Rules target instances by **network tag** or **service account**. Every VPC has implied rules: deny all ingress, allow all egress.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Commands that change state are marked **change**.

## 1. Inventory

```bash
gcloud compute networks list
gcloud compute networks subnets list --format="table(name, region.basename(), network.basename(), ipCidrRange, privateIpGoogleAccess, logConfig.enable)"
gcloud compute routers list                         # Cloud Routers / Cloud NAT
gcloud compute shared-vpc get-host-project <SERVICE_PROJECT_ID>
```

The `default` network (auto-mode, with permissive `default-allow-ssh`, `default-allow-rdp`, `default-allow-icmp`) should not exist in production. Block it with the constraint `compute.skipDefaultNetworkCreation`.

## 2. Find rules open to the internet

```bash
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND disabled=false AND sourceRanges:0.0.0.0/0" \
  --format="table(name, network.basename(), priority, allowed[].map().firewall_rule().list(), targetTags.list(), targetServiceAccounts.list())"

gcloud asset search-all-resources --scope=organizations/<ORG_ID> \
  --asset-types=compute.googleapis.com/Firewall --query="sourceRanges:0.0.0.0/0"

gcloud compute firewall-policies list --organization=<ORG_ID>
gcloud compute network-firewall-policies list --global
```

A rule with no target tags applies to **every instance** in the network.

```bash
# change: restrict SSH to the IAP range
gcloud compute firewall-rules update default-allow-ssh --source-ranges=35.235.240.0/20
```

## 3. Effective firewalls for one VM

```bash
gcloud compute instances network-interfaces get-effective-firewalls <vm> --zone=<zone>
```

This merges hierarchical policies, network policies and VPC rules in evaluation order, the quickest answer to "why is this port open/closed?". For path analysis use [Connectivity Tests](troubleshooting.md#3-cannot-reach-a-vm).

## 4. VPC flow logs and firewall rule logs

```bash
# change: enable flow logs on a subnet (sampled; costs Logging ingestion)
gcloud compute networks subnets update <subnet> --region=<region> \
  --enable-flow-logs --logging-flow-sampling=0.5 --logging-aggregation-interval=interval-5-sec
# change: log hits on a firewall rule
gcloud compute firewall-rules update <rule> --enable-logging
```

```bash
gcloud logging read 'resource.type="gce_subnetwork" AND log_id("compute.googleapis.com/vpc_flows")
  AND jsonPayload.connection.dest_port=22 AND jsonPayload.reporter="DEST"' \
  --freshness=1d --limit=50 --format="table(timestamp, jsonPayload.connection.src_ip, jsonPayload.connection.dest_ip, jsonPayload.bytes_sent)"

gcloud logging read 'log_id("compute.googleapis.com/firewall") AND jsonPayload.disposition="DENIED"' --freshness=1h --limit=50
```

For volume, route flow logs to BigQuery ([Monitoring & log queries](monitoring-logs.md#4-bigquery-log-sinks)).

## 5. Keep traffic private

| Control | Effect |
| :--- | :--- |
| **Private Google Access** | VMs without external IPs reach Google APIs |
| **Cloud NAT** | Outbound internet without external IPs; NAT logs show connections |
| **Private Service Connect** | Private endpoints for Google APIs and published services |
| **VPC Service Controls** | Perimeter around projects so data in Cloud Storage, BigQuery and others cannot be copied out, even with valid credentials |

```bash
gcloud access-context-manager perimeters list --policy=<ACCESS_POLICY_ID>
gcloud access-context-manager perimeters describe <perimeter> --policy=<ACCESS_POLICY_ID>
```

VPC Service Controls is the main defense against stolen-credential data exfiltration; violations appear in audit logs with `protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"`.

## Related

- [Compute Engine](compute.md)
- [Incident response → Isolate a VM](incident-response.md#2-isolate-a-vm)
- [Detection: DoS flood](../../detection/sigma/dos-flood.md)

## Sources

- [VPC firewall rules](https://cloud.google.com/firewall/docs/firewalls)
- [Hierarchical firewall policies](https://cloud.google.com/firewall/docs/firewall-policies)
- [VPC Flow Logs](https://cloud.google.com/vpc/docs/flow-logs)
- [VPC Service Controls overview](https://cloud.google.com/vpc-service-controls/docs/overview)
