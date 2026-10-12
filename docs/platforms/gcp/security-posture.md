---
title: Security Command Center (GCP Posture & Alerts)
platforms: [GCP]
languages: [Bash]
tasks: [Assurance, Hardening, Investigation, Incident Response]
category: Posture
tags: [gcp, security command center, scc, security health analytics, event threat detection, container threat detection, findings, mute rules, cis benchmark]
aliases: [gcloud scc findings list, gcp security command center findings, event threat detection findings, scc mute rule, gcp cis benchmark compliance, scc notification pubsub]
difficulty: intermediate
verified: false
---

# Security Command Center (GCP Posture & Alerts)

**Security Command Center (SCC)** collects findings from Google's built-in detectors and partners. Which detectors you get depends on the tier (Standard, Premium, Enterprise):

| Service | Finds | Tier |
| :--- | :--- | :--- |
| **Security Health Analytics** | Misconfigurations (public buckets, open firewalls, SA keys, MFA) | Standard (subset), Premium |
| **Event Threat Detection** | Threats in logs: IAM anomalies, malware domains, crypto mining, exfiltration | Premium |
| **Container Threat Detection** | Runtime attacks in GKE nodes and containers | Premium |
| **VM Threat Detection** | Crypto miners and kernel rootkits from VM memory | Premium |
| **Web Security Scanner** | OWASP issues in App Engine / GKE / Compute apps | Standard (managed scans: Premium) |
| **Attack path simulation**, **compliance reports** (CIS, PCI DSS, NIST) | Exposure of high-value resources | Premium |

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. List active findings

```bash
gcloud scc findings list organizations/<ORG_ID> --location=global \
  --filter='state="ACTIVE" AND mute!="MUTED" AND (severity="CRITICAL" OR severity="HIGH")' \
  --format="table(finding.category, finding.severity, finding.resourceName.basename(), finding.eventTime)"

gcloud scc findings list organizations/<ORG_ID> --location=global \
  --filter='state="ACTIVE" AND finding_class="THREAT"' --format=json > threats.json
```

`finding_class` values include `THREAT`, `VULNERABILITY`, `MISCONFIGURATION`, `OBSERVATION`. Older commands without `--location` use SCC API v1; newer setups use data residency locations.

## 2. Common categories

| Category | Meaning | Fix in |
| :--- | :--- | :--- |
| `PUBLIC_BUCKET_ACL` | Bucket readable by `allUsers`/`allAuthenticatedUsers` | [Storage](storage.md#2-find-exposed-buckets) |
| `OPEN_FIREWALL`, `OPEN_SSH_PORT`, `OPEN_RDP_PORT` | Ingress from `0.0.0.0/0` | [Networking](networking.md#2-find-rules-open-to-the-internet) |
| `USER_MANAGED_SERVICE_ACCOUNT_KEY`, `SERVICE_ACCOUNT_KEY_NOT_ROTATED` | Downloadable SA keys | [IAM](identity-access.md#3-service-accounts-and-keys) |
| `PRIMITIVE_ROLES_USED`, `OVER_PRIVILEGED_SERVICE_ACCOUNT_USER` | Owner/Editor grants | [IAM](identity-access.md#2-risky-roles) |
| `AUDIT_LOGGING_DISABLED` | Data Access logs off | [Audit logging](audit-logging.md#3-turn-on-data-access-logs) |
| `Persistence: IAM Anomalous Grant` | Sensitive role granted to an outside principal | [Persistence](persistence-hunting.md) |
| `Execution: Cryptocurrency Mining Hash Match` | Miner detected | [Incident response](incident-response.md) |
| `Exfiltration: BigQuery Data Exfiltration` | Table copied outside the org | [Incident response](incident-response.md#4-scope-the-intrusion) |

## 3. Work a finding

```bash
gcloud scc findings list organizations/<ORG_ID> --location=global \
  --filter='category="OPEN_FIREWALL" AND state="ACTIVE"' --format=json | jq '.[0].finding | {resourceName, sourceProperties, nextSteps}'

# change: mark resolved after fixing (detectors re-open it if still present)
gcloud scc findings update <FINDING_NAME> --state=INACTIVE
```

Threat findings include `sourceProperties` with the triggering log entry (`evidence`, `properties.sensitiveRoleGrant`, IPs), which is your starting point in [Audit logging](audit-logging.md#1-quick-lookups).

## 4. Mute rules (accepted risk, noise)

```bash
# change: mute findings on a sandbox folder
gcloud scc muteconfigs create mute-sandbox --organization=<ORG_ID> --location=global \
  --description="Sandbox folder accepted risk" \
  --filter='resource.folders.resource_folder="folders/<FOLDER_ID>" AND category="OPEN_FIREWALL"' --type=STATIC
gcloud scc muteconfigs list --organization=<ORG_ID> --location=global
```

Review mute rules regularly; an attacker with SCC admin rights can hide findings with them. Changes appear in audit logs as `CreateMuteConfig` / `UpdateMuteConfig`.

## 5. Send findings to a SIEM or chat

```bash
# change: continuous export to Pub/Sub
gcloud scc notifications create scc-high --organization=<ORG_ID> --location=global \
  --pubsub-topic=projects/<SEC_PROJECT>/topics/scc-findings \
  --filter='state="ACTIVE" AND (severity="HIGH" OR severity="CRITICAL")'
```

Or export continuously to BigQuery for trending and to join with [audit logs](monitoring-logs.md#4-bigquery-log-sinks).

## 6. Without SCC Premium

- Security Health Analytics Standard still covers the most common misconfigurations.
- Build the rest from [log-based alerts](monitoring-logs.md#5-log-based-metrics-and-alerts), [Cloud Asset Inventory](resource-hierarchy.md#2-search-every-resource-cloud-asset-inventory) searches and [Org Policy](policy-governance.md).

## Related

- [Policy & governance](policy-governance.md)
- [Concept: vulnerability management](../../fundamentals/concepts/vulnerability-management.md)
- [Task: assurance](../../tasks/assurance/index.md)

## Sources

- [Security Command Center overview](https://cloud.google.com/security-command-center/docs/security-command-center-overview)
- [Security Health Analytics findings](https://cloud.google.com/security-command-center/docs/concepts-vulnerabilities-findings)
- [Event Threat Detection overview](https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview)
- [Mute findings](https://cloud.google.com/security-command-center/docs/how-to-mute-findings)
