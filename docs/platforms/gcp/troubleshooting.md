---
title: Google Cloud Troubleshooting
platforms: [GCP]
languages: [Bash]
tasks: [Troubleshooting, Administration]
category: Troubleshooting
tags: [gcp, troubleshooting, permission denied, api not enabled, quota, connectivity tests, policy troubleshooter, gcloud verbosity, iap]
aliases: [gcp permission denied 403, gcp api has not been used in project, gcloud services enable, gcp policy troubleshooter, gcp connectivity test, gcloud debug log-http]
difficulty: basic
verified: false
---

# Google Cloud Troubleshooting

Most Google Cloud failures are one of: **wrong identity or project**, **missing permission**, **API not enabled**, **an Org Policy or VPC Service Controls block**, **firewall or routing**, or **quota**. Work through them in that order.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Permission denied and authentication errors

| Message | Likely cause | Check |
| :--- | :--- | :--- |
| `PERMISSION_DENIED: ... does not have <permission>` | Missing role, or wrong project | `gcloud config list`; [Policy Troubleshooter](#2-is-a-policy-the-cause) |
| `Request is prohibited by organization's policy. vpcServiceControlsUniqueIdentifier: ...` | VPC Service Controls perimeter | Search the identifier in logs (below) |
| `Constraint constraints/<name> violated` | Organization Policy | `gcloud org-policies describe <name> --project=<p> --effective` |
| `Reauthentication failed` / `invalid_grant` | Expired gcloud or ADC login | `gcloud auth login`; `gcloud auth application-default login` |
| `Caller does not have permission 'iam.serviceAccounts.getAccessToken'` | Impersonation without Token Creator | Grant `roles/iam.serviceAccountTokenCreator` on the SA |
| `insufficient authentication scopes` | VM access scopes too narrow | Set `cloud-platform` scope ([Compute](compute.md#4-service-accounts-and-metadata)) |

```bash
gcloud auth list && gcloud config list                       # who and which project
gcloud logging read 'protoPayload.status.code=7 AND protoPayload.authenticationInfo.principalEmail="<you>"' --freshness=1h --limit=5 \
  --format="yaml(protoPayload.methodName, protoPayload.authorizationInfo, protoPayload.status.message)"
gcloud logging read 'protoPayload.metadata.vpcServiceControlsUniqueId="<id>"' --freshness=1d --format=json
```

## 2. Is a policy the cause?

```bash
gcloud policy-intelligence troubleshoot-policy iam \
  //cloudresourcemanager.googleapis.com/projects/<PROJECT_ID> \
  --principal-email=alice@example.com --permission=compute.instances.start
```

The output shows each allow and deny policy in the hierarchy and whether it grants, denies or does not apply. It also covers IAM conditions (time, resource tags) that a plain policy read misses.

## 3. Cannot reach a VM

```bash
# change: creates a test resource (no traffic is sent; it analyses configuration)
gcloud network-management connectivity-tests create ssh-test \
  --source-ip-address=203.0.113.10 --destination-instance=projects/<p>/zones/<zone>/instances/<vm> \
  --destination-port=22 --protocol=TCP
gcloud network-management connectivity-tests describe ssh-test --format="yaml(reachabilityDetails)"
gcloud compute instances network-interfaces get-effective-firewalls <vm> --zone=<zone>
```

| Symptom | Cause |
| :--- | :--- |
| IAP SSH: `failed to connect to backend` | No firewall rule from `35.235.240.0/20`, or sshd down |
| IAP SSH: `4033 not authorized` | Missing `roles/iap.tunnelResourceAccessor` |
| SSH key rejected | OS Login on but missing `roles/compute.osLogin`, or key only in metadata |
| No internet from private VM | No Cloud NAT on that region/subnet |
| Cannot reach Google APIs from private VM | Private Google Access off on the subnet |

Use the serial console output when the guest itself is broken ([Compute](compute.md#7-serial-port-output-boot-problems-evidence)).

## 4. API not enabled

`API [compute.googleapis.com] not enabled on project` or `... has not been used in project <number> before or it is disabled`:

```bash
gcloud services list --enabled --project=<PROJECT_ID> | grep -i compute
gcloud services enable compute.googleapis.com cloudasset.googleapis.com --project=<PROJECT_ID>   # change
```

For tools such as Cloud Asset Inventory, the API must be enabled in the **quota project** (the project gcloud bills the call to), not only the target: `gcloud config set billing/quota_project <p>`.

## 5. Quotas and rate limits

```bash
gcloud compute regions describe <region> --format="table(quotas.metric, quotas.limit, quotas.usage)"
gcloud logging read 'protoPayload.status.code=8' --freshness=1d --limit=10     # RESOURCE_EXHAUSTED
```

Errors `429` / `RESOURCE_EXHAUSTED` / `rateLimitExceeded`: back off and retry with jitter; request increases in **IAM & Admin → Quotas**.

## 6. CLI problems

```bash
gcloud info                                 # paths, account, project, Python used
gcloud <command> --verbosity=debug          # full error and retry detail
gcloud <command> --log-http                 # every HTTP request (contains tokens: do not share raw)
gcloud config configurations list           # are you in the configuration you think?
```

Windows: run `gcloud` from a fresh PowerShell after install so `PATH` updates; proxies need `gcloud config set proxy/type http` plus `proxy/address` and `proxy/port`.

## 7. Where to look next

- [Audit logging](audit-logging.md#2-read-an-audit-entry) for the exact `status` and `authorizationInfo` of a failed call
- **Personalized Service Health** and the Google Cloud status dashboard for provider outages
- `gcloud support cases create` with a paid support plan

## Related

- [CLI & authentication](cli-authentication.md)
- [Networking](networking.md)
- [Identity & access](identity-access.md)

## Sources

- [Troubleshoot IAM permissions (Policy Troubleshooter)](https://cloud.google.com/policy-intelligence/docs/troubleshoot-access)
- [Connectivity Tests overview](https://cloud.google.com/network-intelligence-center/docs/connectivity-tests/concepts/overview)
- [Troubleshoot IAP TCP forwarding](https://cloud.google.com/iap/docs/troubleshooting-tcp-forwarding)
- [VPC Service Controls troubleshooting](https://cloud.google.com/vpc-service-controls/docs/troubleshooting)
