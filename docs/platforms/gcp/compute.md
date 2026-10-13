---
title: Google Compute Engine & OS Login
platforms: [GCP]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Compute
tags: [gcp, compute engine, os login, ssh keys, metadata, startup script, shielded vm, iap tunnel, serial console]
aliases: [gcloud compute instances list, gcloud compute ssh, gcp os login enable, gcp startup script, gcp serial port output, gcloud compute ssh tunnel-through-iap]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Google Compute Engine & OS Login

Compute Engine VMs get their identity from an **attached service account** and their configuration from **metadata** (SSH keys, startup scripts, guest attributes). Whoever can edit metadata can usually run code as root, so metadata permissions are as sensitive as SSH access.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Commands that change state are marked **change**.

## 1. Inventory

```bash
gcloud compute instances list \
  --format="table(name, zone.basename(), status, networkInterfaces[0].networkIP, networkInterfaces[0].accessConfigs[0].natIP, serviceAccounts[0].email)"
gcloud compute instances describe <vm> --zone=<zone> --format=json > vm.json
gcloud asset search-all-resources --scope=organizations/<ORG_ID> --asset-types=compute.googleapis.com/Instance
```

VMs with an external `natIP` and the default compute service account with `cloud-platform` scope are the first ones to review.

## 2. Connect

| Method | When |
| :--- | :--- |
| `gcloud compute ssh <vm> --tunnel-through-iap` | No external IP needed; access controlled by `roles/iap.tunnelResourceAccessor` |
| OS Login (`enable-oslogin=TRUE`) | SSH tied to the Google identity, with 2FA option and `roles/compute.osAdminLogin` |
| Serial console | Last resort when networking is broken; disable by default |

```bash
gcloud compute ssh <vm> --zone=<zone> --tunnel-through-iap
gcloud compute start-iap-tunnel <vm> 3389 --local-host-port=localhost:13389 --zone=<zone>   # RDP to Windows
```

IAP TCP forwarding needs a firewall rule allowing `35.235.240.0/20` to the port.

## 3. OS Login and SSH keys

```bash
# change: enforce OS Login on the whole project
gcloud compute project-info add-metadata --metadata=enable-oslogin=TRUE
gcloud compute project-info describe --format="value(commonInstanceMetadata.items)"   # look for ssh-keys
gcloud compute instances describe <vm> --zone=<zone> --format="value(metadata.items)"
```

With OS Login off, any `ssh-keys` entry in project or instance metadata creates a Linux user with sudo. Enforce OS Login org-wide with the constraint `compute.requireOsLogin`.

## 4. Service accounts and metadata

```bash
gcloud compute instances describe <vm> --zone=<zone> --format="yaml(serviceAccounts)"
# change: swap to a dedicated least-privilege SA (VM must be stopped)
gcloud compute instances set-service-account <vm> --zone=<zone> \
  --service-account=app-vm@<PROJECT_ID>.iam.gserviceaccount.com --scopes=cloud-platform
```

Give each workload its own service account with narrow roles and use `cloud-platform` scope; control access through IAM, not scopes. Startup scripts (`startup-script`, `startup-script-url`, `windows-startup-script-ps1`) run as root/SYSTEM on every boot: review them like code.

## 5. Harden

```bash
# change: Shielded VM features
gcloud compute instances update <vm> --zone=<zone> --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
# change: block serial port access project-wide
gcloud compute project-info add-metadata --metadata=serial-port-enable=FALSE
gcloud compute instances get-shielded-identity <vm> --zone=<zone>
```

Org Policy constraints that matter: `compute.vmExternalIpAccess`, `compute.requireShieldedVm`, `compute.disableSerialPortAccess`, `compute.requireOsLogin` ([Policy & governance](policy-governance.md#2-security-constraints-to-set)).

## 6. Run a command on many VMs

Google Cloud has no direct equivalent of SSM Run Command. Options:

- **VM Manager OS policies** (`gcloud compute os-config os-policy-assignments`) for desired state.
- **OS inventory** for installed packages: `gcloud compute os-config inventories list --location=<zone>`.
- Loop `gcloud compute ssh <vm> --tunnel-through-iap --command="..."` for ad-hoc triage.

```bash
for vm in $(gcloud compute instances list --filter="labels.role=web" --format="value(name,zone.basename())" | tr '\t' ','); do
  gcloud compute ssh "${vm%,*}" --zone="${vm#*,}" --tunnel-through-iap --command="uptime; last -n 5" 2>&1 | sed "s/^/${vm%,*}: /"
done
```

## 7. Serial port output (boot problems, evidence)

```bash
gcloud compute instances get-serial-port-output <vm> --zone=<zone> --port=1 > serial-$(date -u +%Y%m%dT%H%M%SZ).log
```

## Related

- [CLI & authentication → Metadata server](cli-authentication.md#6-metadata-server)
- [Incident response → Isolate a VM](incident-response.md#2-isolate-a-vm)
- [Networking](networking.md)

## Sources

- [About OS Login](https://cloud.google.com/compute/docs/oslogin)
- [Use IAP for TCP forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding)
- [Service accounts for Compute Engine](https://cloud.google.com/compute/docs/access/service-accounts)
- [Shielded VM](https://cloud.google.com/compute/shielded-vm/docs/shielded-vm)
