---
title: GCP Security Baseline — CIS Google Cloud Foundations Benchmark & Security Command Center
type: entry
platforms:
  - GCP
languages:
  - Bash
tasks:
  - Hardening
  - Assurance
  - Governance
category: Workflow
security_domain: Cloud
author: RJGProjectz
date_created: 2026-10-24
last_updated: 2026-10-24
verified: false
difficulty: advanced
tags:
  - cis-benchmark
  - cis-gcp-foundations
  - nist-csf
  - baseline
  - gcp
  - google-cloud
  - security-command-center
  - cloud-audit-logs
  - organization-policy
  - public-access-prevention
  - iam-least-privilege
  - os-login
  - cloud-kms
aliases:
  - gcp security baseline
  - harden gcp organization
  - cis google cloud foundations benchmark
  - security command center cis
  - gcp public access prevention
  - disable service account keys
  - gcp org policy constraints
  - block legacy metadata endpoints
---

# GCP Security Baseline — CIS Google Cloud Foundations Benchmark & Security Command Center
> **Created**: 2026-10-24T00:00:00Z
> **Last Modified**: 2026-10-24T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands. Before running any script:
> 1. Verify the script integrity and test in a non-production project.
> 2. Ensure you are in a `Test`/`Dev` project (never the organization or a production project first).
> 3. `gcloud` has no universal `--dry-run` for write actions — **audit with `describe`/`list`/`get-iam-policy` first**, read the output, then apply the change. Many commands accept `--impersonate-service-account` and `--log-http` for safe inspection.
> 4. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The commands and settings below follow the documented behaviour of the Google Cloud CLI (`gcloud`),
    the **CIS Google Cloud Platform Foundation Benchmark** and the Security Command Center / service docs
    cited at the foot of this page, but have **not** been lab-run against a live organization for this
    page. CIS control numbers shift between benchmark versions — confirm each against the benchmark
    version your Security Command Center compliance view reports. Organization-wide changes (public access
    prevention, `disableServiceAccountKeyCreation`, OS Login, external-IP and serial-port constraints)
    **can break working workloads and locked-out access paths** — stage them per project, watch Cloud
    Audit Logs and application logs, and confirm before production. Remove this block when `verified: true`.

This is the **GCP counterpart** to the [AWS Security Baseline](cloud-aws-security-baseline.md) and the
[Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md), and the defensive answer to the
findings in [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md).
Each control below is tied, where relevant, to the offensive finding it closes — public storage,
over-permissioned IAM / service-account keys, and the SSRF → metadata-server credential-theft pivot.
Remediation principles map to [Cloud-Native Security](../../fundamentals/concepts/cloud-native-security.md).
Settings are aligned with the **CIS Google Cloud Platform Foundation Benchmark** and **NIST Cybersecurity
Framework (CSF) 2.0** (`PR.AA-01`, `PR.DS-01`, `DE.CM-01`, `GV.PO-01`).

---

## 1. Compliance alignment matrix

| CIS GCP control (indicative) | NIST CSF 2.0 | Target service | Baseline enforcement standard | Closes offensive finding |
|:---|:---|:---|:---|:---|
| **1.1 / 1.2 / 1.3** | `PR.AA-01` | Org IAM / identities | Corporate SSO, 2-Step Verification enforced; minimise Org-level `roles/owner`; separation of duties. | Account takeover · over-broad org admin |
| **1.4 / 1.5 / 1.6** | `PR.AA-01` | Service accounts | No user-managed SA keys; no default SA with broad scope; least-privilege SA usage. | Stolen/long-lived SA keys |
| **1.8 / 1.9 / 1.10** | `PR.AA-01` | IAM roles | Avoid primitive roles (`owner`/`editor`); predefined/custom least-privilege roles; rotate API keys & restrict them. | Over-permissioned IAM |
| **2.1 / 2.2 / 2.x** | `DE.CM-01` | Cloud Audit Logs | Admin Activity always on; **Data Access** logs enabled; log sinks + metric alerts for IAM/firewall/audit-config changes. | Unlogged activity |
| **2.12 / asset** | `DE.CM-01` | Cloud Asset Inventory | Inventory + change feed enabled. | Drift / no inventory |
| **5.1 / 5.2** | `PR.DS-01` | Cloud Storage | **Public Access Prevention** (org policy) + **Uniform bucket-level access**; CMEK default encryption. | Public buckets · data exposure |
| **1.x / SCC** | `DE.CM-01` | Security Command Center | SCC enabled org-wide with the **CIS GCP Foundation Benchmark** posture; Event Threat Detection on. | Undetected credential abuse |
| **3.6 / 3.7 / 3.x** | `PR.IR-01` | VPC firewall | No firewall rule allows `0.0.0.0/0` → 22/3389; no default network; VPC Flow Logs on. | Exposed management ports |
| **1.10 / disk** | `PR.DS-01` | Cloud KMS | Customer-managed keys (CMEK) with rotation for data/disks at rest. | Unencrypted data at rest |
| **4.6 / 4.8 / 4.9 / 4.11** | `PR.IR-01` | Compute Engine VMs | OS Login on; block project-wide SSH keys; serial port off; Shielded VM; **`disable-legacy-endpoints=true`**. | **SSRF → metadata credential theft** |

---

## 2. Organization & resource-hierarchy lockdown

The **Organization** node is the highest-value identity boundary in GCP; everything inherits from it.
Audit who holds organization-level `roles/owner` / `roles/organizationAdmin`, enforce 2-Step Verification
through Cloud Identity / Workspace, and keep day-to-day work in projects — not at the org.

```bash
ORG_ID="123456789012"   # gcloud organizations list

# Who holds org-level roles? Flag broad grants (owner / organizationAdmin / billing) [CIS 1.x]
gcloud organizations get-iam-policy "$ORG_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.role:(roles/owner OR roles/resourcemanager.organizationAdmin)" \
  --format="table(bindings.role, bindings.members)"
```

- Enforce **2-Step Verification** (and ideally phishing-resistant keys) for all users in the Cloud
  Identity / Workspace admin console; disable password-only sign-in. There is no project-level MFA knob —
  it is governed at the identity provider.
- Keep a small, audited set of **Organization Admins**; use folders to delegate, and apply the
  Organization Policy constraints in §10 at the org node so every project inherits the baseline.

---

## 3. IAM least privilege & service-account hygiene

The cloud perimeter is identity. Forbid the primitive roles, eliminate user-managed service-account keys,
and prefer short-lived credentials — this closes the **over-permissioned IAM** and **stolen SA key**
findings from the enumeration page.

```bash
PROJECT_ID="my-project"

# 1. Find primitive-role grants (owner/editor) on the project [CIS 1.8]
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.role:(roles/owner OR roles/editor)" \
  --format="table(bindings.role, bindings.members)"

# 2. Find user-managed (long-lived) service-account keys — these should not exist [CIS 1.4]
for SA in $(gcloud iam service-accounts list --project "$PROJECT_ID" --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account="$SA" \
    --managed-by=user --format="table(name, validAfterTime)" --filter="keyType=USER_MANAGED"
done
```

- **No user-managed SA keys.** Forbid their creation org-wide with the
  `constraints/iam.disableServiceAccountKeyCreation` org policy (§10). Workloads authenticate with
  **Workload Identity Federation** (external) or **Workload Identity** (GKE) and attached service accounts;
  developers use `gcloud auth login` with short-lived tokens, not downloaded keys.
- **Replace primitive roles** (`owner`/`editor`/`viewer`) with **predefined** or **custom least-privilege**
  roles. `editor` on the default compute service account is a common over-grant.
- Use **IAM Recommender** to surface and strip unused permissions, and restrict **API keys** to specific
  APIs and referrers. Separate duties so no single principal both administers logging and can delete logs.

→ Platform depth: [GCP Identity & Access (IAM)](../../platforms/gcp/identity-access.md)

---

## 4. Cloud Audit Logs & Asset Inventory

Admin Activity logs are always on, but **Data Access logs are off by default** — without them the read
enumeration on the offensive page is invisible. Enable Data Access logging and route everything to a
locked, retained log bucket in a separate logging project.

```bash
# Audit: is Data Access logging configured? Look at the auditConfigs block [CIS 2.1]
gcloud projects get-iam-policy "$PROJECT_ID" --format="yaml(auditConfigs)"

# Create an aggregated org sink to a central logging bucket/BigQuery for retention & analysis [CIS 2.2]
gcloud logging sinks create org-audit-sink \
  storage.googleapis.com/projects/_/buckets/BUCKET_OR_DATASET \
  --organization="$ORG_ID" --include-children \
  --log-filter='logName:"cloudaudit.googleapis.com"'
```

- Enable **Data Access** audit logs (`DATA_READ`/`DATA_WRITE`) on sensitive services via each project's IAM
  `auditConfigs`, and protect the audit-config itself with a log-based metric alert on changes (CIS 2.5).
- Add **log-based metric alerts** for the CIS 2.x change events: project ownership assignments, audit-config
  changes, custom-role changes, VPC firewall/route/network changes, and Cloud SQL config changes.
- Turn on **Cloud Asset Inventory** feeds for a continuous resource inventory and change history.

→ Platform depth: [GCP Cloud Audit Logs](../../platforms/gcp/audit-logging.md) · [GCP Monitoring & Logs](../../platforms/gcp/monitoring-logs.md)

---

## 5. Cloud Storage — public access prevention & encryption

Public buckets are the single most common cloud data-exposure finding — the first thing the offensive page
checks unauthenticated. Enforce **Public Access Prevention** (org-wide) and **Uniform bucket-level access**,
and set CMEK default encryption. This closes the **public bucket / data exposure** finding.

```bash
# Audit: find buckets that are NOT enforcing public access prevention [CIS 5.1]
for B in $(gcloud storage buckets list --project "$PROJECT_ID" --format="value(name)"); do
  gcloud storage buckets describe "gs://$B" \
    --format="value(name, publicAccessPrevention, uniformBucketLevelAccess.enabled)"
done

# Enforce public access prevention + uniform bucket-level access on a bucket [CIS 5.1 / 5.2]
gcloud storage buckets update "gs://my-sensitive-bucket" \
  --public-access-prevention \
  --uniform-bucket-level-access

# Default encryption with a Cloud KMS customer-managed key (CMEK)
gcloud storage buckets update "gs://my-sensitive-bucket" \
  --default-encryption-key="projects/$PROJECT_ID/locations/us/keyRings/data/cryptoKeys/bucket-key"
```

The org-level `constraints/storage.publicAccessPrevention` constraint (§10) is the backstop: it enforces
prevention on every current and future bucket, so a misconfigured ACL or IAM grant cannot expose data.
Uniform bucket-level access disables per-object ACLs, so access is governed only by IAM.

→ Platform depth: [GCP Cloud Storage & Data Exposure](../../platforms/gcp/storage.md)

---

## 6. Security Command Center + CIS GCP benchmark + Event Threat Detection

Turn on continuous posture scoring and threat detection — this is how you **detect** the credential abuse
that follows a successful enumeration, and measure the controls on this page.

```bash
# List SCC services / settings at the organization (requires SCC admin) [CIS SCC]
gcloud scc settings services describe --organization="$ORG_ID" \
  --service=event-threat-detection 2>/dev/null || \
  echo "Enable Security Command Center (Premium/Enterprise) in the console for ETD + compliance posture"

# Review active findings (e.g. public buckets, over-permissioned IAM, open firewall)
gcloud scc findings list "organizations/$ORG_ID" \
  --filter="state=\"ACTIVE\"" --format="table(category, resourceName, severity)" 2>/dev/null
```

Enable **Security Command Center** org-wide. The **CIS GCP Foundation Benchmark** posture gives a
continuous pass/fail against the controls on this page; **Event Threat Detection** flags anomalous IAM
grants, service-account key abuse, data exfiltration, and the metadata-credential-theft pattern.
Aggregate findings to a single security project and alert on new high-severity findings.

→ Platform depth: [GCP Security Command Center & Posture](../../platforms/gcp/security-posture.md)

---

## 7. VPC firewall rules & flow logs

Management ports open to the internet are the classic initial-access finding. Remove the **default
network**, lock inbound SSH/RDP, and turn on flow logs for network evidence.

```bash
# Find firewall rules allowing 0.0.0.0/0 inbound to SSH(22) or RDP(3389) [CIS 3.6 / 3.7]
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges:0.0.0.0/0 AND (allowed.ports:22 OR allowed.ports:3389)" \
  --format="table(name, network, sourceRanges.list(), allowed[].map().firewall_rule().list())"

# Delete an over-permissive public SSH rule once identified
gcloud compute firewall-rules delete default-allow-ssh-wide --quiet

# Enable VPC Flow Logs on a subnet for network evidence [CIS 3.x]
gcloud compute networks subnets update my-subnet --region=us-central1 \
  --enable-flow-logs --logging-aggregation-interval=interval-5-sec --logging-flow-sampling=0.5
```

Reach VMs through **Identity-Aware Proxy (IAP) TCP forwarding**, not public IPs — allow SSH only from the
IAP range `35.235.240.0/20` and give VMs no external IP (§9/§10). Remove the auto-created **default
network** and its permissive rules; build least-privilege VPCs instead.

→ Platform depth: [GCP VPC & Networking](../../platforms/gcp/networking.md)

---

## 8. Cloud KMS encryption at rest

Use **customer-managed encryption keys (CMEK)** with rotation for data, disks and buckets, so access is
governed by key IAM and logged in Cloud Audit Logs.

```bash
# Create a key ring and a rotating CMEK (90-day rotation) [CIS 1.10 family]
gcloud kms keyrings create data --location=us 2>/dev/null
gcloud kms keys create bucket-key --location=us --keyring=data --purpose=encryption \
  --rotation-period=90d --next-rotation-time="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)"

# Verify rotation is set on existing keys
gcloud kms keys list --location=us --keyring=data \
  --format="table(name, rotationPeriod, nextRotationTime)"
```

Attach CMEK to new persistent disks (`gcloud compute disks create ... --kms-key=...`) and to Cloud Storage,
BigQuery and Cloud SQL where data sensitivity requires auditable, revocable keys. Scope key IAM tightly
(which principals may `cloudkms.cryptoKeyVersions.useToDecrypt`).

→ Platform depth: [GCP Cloud KMS & Secrets](../../platforms/gcp/keys-secrets.md)

---

## 9. VM metadata hardening & the SSRF → metadata pivot

This is the control set that **directly closes the SSRF → metadata-server credential-theft pivot**
documented in the offensive page. The GCP metadata server (`metadata.google.internal` / `169.254.169.254`)
hands out the attached service account's OAuth token. The v1 endpoint requires a `Metadata-Flavor: Google`
header, which blocks naive SSRF — but **legacy endpoints (`/0.1/`, `/v1beta1/`) do not**, so they are the
SSRF risk. Disable them, and reduce the blast radius of a stolen token.

```bash
# Audit: which instances still allow legacy metadata endpoints? (look for disable-legacy-endpoints) [CIS 4.x]
gcloud compute instances describe my-vm --zone=us-central1-a \
  --format="value(metadata.items.filter('key:disable-legacy-endpoints').extract('value'))"

# Harden an instance: disable legacy endpoints, block project-wide SSH keys, OS Login, serial port off
gcloud compute instances add-metadata my-vm --zone=us-central1-a \
  --metadata=disable-legacy-endpoints=true,block-project-ssh-keys=true,enable-oslogin=true,serial-port-enable=false

# Shielded VM (secure boot + vTPM + integrity monitoring) on an existing instance
gcloud compute instances update my-vm --zone=us-central1-a \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

- **Least-scope service accounts.** A stolen token is only as powerful as the VM's attached SA. Never run
  VMs as the **default compute service account with the `cloud-platform` scope** — attach a dedicated,
  least-privilege SA (closes the enumeration page's "VM → metadata → broad cloud access" chain).
- Enforce these fleet-wide with the org policy constraints in §10 (`compute.requireOsLogin`,
  `compute.disableSerialPortAccess`, `compute.vmExternalIpAccess`) rather than per instance.
- Pair with the SSRF fixes in [SSRF defense](../../fundamentals/web-apps/ssrf-defense.md) — defence in depth
  closes the pivot from both the application and the metadata ends.

→ Platform depth: [GCP Compute Engine](../../platforms/gcp/compute.md)

---

## 10. Organization Policy constraints (the baseline, enforced)

Organization Policy is GCP's preventive guardrail — the equivalent of an AWS SCP or Azure Policy. Setting
these at the **organization** node makes the baseline inherited and un-bypassable by project owners.

```bash
# Example: forbid service-account key creation org-wide [CIS 1.4]
gcloud org-policies set-policy - <<EOF
name: organizations/$ORG_ID/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
  - enforce: true
EOF

# Review which constraints are currently enforced
gcloud org-policies list --organization="$ORG_ID" --format="table(constraint, spec.rules[0].enforce)"
```

Baseline constraints to enforce at the org (confirm names against the current constraint catalogue):

| Constraint | Effect | Closes |
|:---|:---|:---|
| `iam.disableServiceAccountKeyCreation` | No user-managed SA keys | Stolen/long-lived keys |
| `iam.automaticIamGrantsForDefaultServiceAccounts` (disable) | Default SAs don't get `editor` | Over-permissioned default SA |
| `storage.publicAccessPrevention` | No public buckets, ever | Public data exposure |
| `storage.uniformBucketLevelAccess` | IAM-only bucket access | ACL exposure |
| `compute.requireOsLogin` | Centralised, IAM-governed SSH | Unmanaged SSH keys |
| `compute.vmExternalIpAccess` (restrict) | VMs have no public IP | Exposed VMs |
| `compute.disableSerialPortAccess` | No interactive serial console | Out-of-band access |
| `compute.skipDefaultNetworkCreation` | No permissive default network | Open-by-default VPC |
| `sql.restrictPublicIp` | Cloud SQL private only | Public database |

---

## Detect it

The baseline above is prevention; pair it with detection. The repository's detection content is currently
Windows/endpoint and Azure/KQL focused — **there is no GCP-native Cloud Audit Logs detection page yet**, so
there is nothing honest to link here. In-platform, the detections are:

- **Security Command Center + Event Threat Detection** (§6) — anomalous IAM grants, service-account key
  creation/abuse, data exfiltration, and the metadata-credential-theft pattern.
- **SCC CIS GCP Foundation Benchmark posture** — a continuous pass/fail against the controls on this page.
- **Cloud Audit Logs + log-based metric alerts** (§4) — alerts for project-ownership assignments,
  audit-config changes, custom-role changes, and firewall/network changes (CIS 2.x).

A vendor-neutral GCP Cloud Audit Logs / IAM detection page (log-based metrics → alerting) is a reasonable
follow-up for the Detection area, mirroring the Azure KQL content.

## Offensive counterpart & related

- **Offensive counterpart:** [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md) — the findings this page closes (public buckets, IAM / SA-key over-permission, metadata/SSRF).
- [AWS Security Baseline](cloud-aws-security-baseline.md) · [Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md) — the sibling cloud baselines.
- [Container & Kubernetes Hardening](container-kubernetes-hardening.md) — GKE-specific hardening.
- Reference: [Cloud-Native Security](../../fundamentals/concepts/cloud-native-security.md) · [Identity & Access Management](../../fundamentals/concepts/identity-access-management.md) · [SSRF defense](../../fundamentals/web-apps/ssrf-defense.md)
- GCP platform depth: [IAM](../../platforms/gcp/identity-access.md) · [Cloud Audit Logs](../../platforms/gcp/audit-logging.md) · [Storage & Data Exposure](../../platforms/gcp/storage.md) · [Security Command Center](../../platforms/gcp/security-posture.md) · [Organization Policy & Governance](../../platforms/gcp/policy-governance.md) · [VPC & Networking](../../platforms/gcp/networking.md) · [Cloud KMS & Secrets](../../platforms/gcp/keys-secrets.md) · [Resource Hierarchy](../../platforms/gcp/resource-hierarchy.md)
- [Hardening — Overview](index.md)

## External resources

- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform) — the control catalogue this page aligns to.
- [Security Command Center documentation](https://cloud.google.com/security-command-center/docs) — posture, compliance standards and Event Threat Detection.
- [Organization Policy constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints) — the preventive guardrail catalogue.
- [Public Access Prevention for Cloud Storage](https://cloud.google.com/storage/docs/public-access-prevention)
- [Protecting the VM metadata server (disable legacy endpoints)](https://cloud.google.com/compute/docs/metadata/overview)
- [Google Cloud Security Foundations Blueprint](https://cloud.google.com/architecture/security-foundations) — the reference architecture.
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
