---
title: Google Cloud Incident Response & Forensics
platforms: [GCP]
languages: [Bash]
tasks: [Incident Response, Forensics, Investigation]
category: Incident Response
tags: [gcp, incident response, disable service account key, revoke tokens, isolate vm, disk snapshot, forensics, evidence, containment]
aliases: [gcp compromised service account key, gcloud iam service-accounts keys disable, gcp isolate compromised vm, gcloud compute snapshots create forensic, gcp revoke user sessions, gcp incident response playbook]
difficulty: advanced
verified: false
---

# Google Cloud Incident Response & Forensics

Order of work: **contain the identity, isolate the workload, preserve evidence, scope, then recover**. Evidence in Google Cloud is mostly audit logs (keep them, see [Audit logging](audit-logging.md)) plus disk snapshots and serial output of affected VMs.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Every command in sections 1, 2 and 5 **changes** state. Agree containment with the system owner first; disabling a service account breaks its workloads.

## 1. Contain the identity

**Service-account key leaked** (most common):

```bash
SA=<sa>@<PROJECT_ID>.iam.gserviceaccount.com
gcloud iam service-accounts keys list --iam-account=$SA --managed-by=user
gcloud iam service-accounts keys disable <KEY_ID> --iam-account=$SA     # reversible; then delete after scoping
gcloud iam service-accounts disable $SA                                  # stops all use, including attached workloads
```

**Impersonation or token theft**: remove the attacker's path to the SA, then wait out tokens (access tokens live up to 1 hour by default, 12 hours if extended).

```bash
gcloud iam service-accounts get-iam-policy $SA
gcloud iam service-accounts remove-iam-policy-binding $SA \
  --member="user:attacker@example.net" --role=roles/iam.serviceAccountTokenCreator
```

**User account compromised**: in the Google Admin console (or Cloud Identity), reset the password, **sign out all sessions** and revoke OAuth tokens and app passwords; then remove their IAM grants ([find them](identity-access.md#4-policy-analyzer)). Cloud Identity session reset is an admin action outside `gcloud`.

**HMAC keys**: `gcloud storage hmac update <ACCESS_ID> --deactivate`.

## 2. Isolate a VM

```bash
VM=<vm>; ZONE=<zone>
# deny-all firewall rules that target a quarantine tag, at top priority
gcloud compute firewall-rules create quarantine-deny-in  --network=<net> --direction=INGRESS --action=DENY --rules=all --source-ranges=0.0.0.0/0 --target-tags=quarantine --priority=0
gcloud compute firewall-rules create quarantine-deny-out --network=<net> --direction=EGRESS  --action=DENY --rules=all --destination-ranges=0.0.0.0/0 --target-tags=quarantine --priority=0
gcloud compute instances add-tags $VM --zone=$ZONE --tags=quarantine
# allow IAP SSH for analysts only if needed: add an ingress ALLOW from 35.235.240.0/20 at priority 0 with the same tag
gcloud compute instances set-service-account $VM --zone=$ZONE --no-service-account --no-scopes   # requires VM stopped
```

Hierarchical firewall policies at a higher level can still **allow** traffic before VPC rules are evaluated (`goto_next` vs `allow`); check [effective firewalls](networking.md#3-effective-firewalls-for-one-vm). Do not stop the VM before deciding on memory capture; stopping loses RAM.

## 3. Preserve evidence

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
gcloud compute instances describe $VM --zone=$ZONE --format=json > $VM-$TS.json
gcloud compute instances get-serial-port-output $VM --zone=$ZONE --port=1 > $VM-serial-$TS.log
for d in $(gcloud compute instances describe $VM --zone=$ZONE --format="value(disks[].source.basename())" | tr ';' ' '); do
  gcloud compute snapshots create "ir-$d-$TS" --source-disk=$d --source-disk-zone=$ZONE \
    --labels=case=<case-id> --storage-location=<region> --description="IR <case-id> by $(gcloud config get account)"
done
```

- Copy snapshots to a **separate forensics project** (create a disk from the snapshot there, or share the snapshot) the attacker cannot reach.
- Memory: run a capture tool inside the guest (LiME, AVML, WinPmem) before shutdown ([memory acquisition](../../tasks/forensics/memory-acquisition-analysis.md)).
- Export relevant logs now: `gcloud logging read '<filter>' --freshness=30d --format=json > logs-$TS.json`. Data Access logs keep only 30 days in `_Default`.
- Hash every exported file (`sha256sum`) and record it in the case notes.

## 4. Scope the intrusion

```bash
# everything done by the compromised principal
gcloud logging read "protoPayload.authenticationInfo.principalEmail=\"$SA\"" --organization=<ORG_ID> --freshness=30d \
  --format="table(timestamp, resource.labels.project_id, protoPayload.methodName, protoPayload.requestMetadata.callerIp)"
# calls made with the leaked key specifically
gcloud logging read 'protoPayload.authenticationInfo.serviceAccountKeyName:"<KEY_ID>"' --freshness=30d
# other identities from the attacker's IP
gcloud logging read 'protoPayload.requestMetadata.callerIp="<ip>"' --freshness=30d
```

Look for: new SA keys, new IAM bindings, new service accounts, Cloud Functions / Cloud Run deployments, compute in unusual regions (mining), `storage.objects.get` bursts, BigQuery `jobs.insert` with exports, and changes to sinks. [Persistence & hunting](persistence-hunting.md) lists the queries; for org-wide scale use the [BigQuery sink](monitoring-logs.md#4-bigquery-log-sinks).

## 5. Contain resources

```bash
gcloud storage buckets update gs://<bucket> --public-access-prevention
gcloud functions delete <fn> --region=<region>          # after exporting its source and config
gcloud compute instances delete <miner-vm> --zone=<zone> --keep-disks=all
gcloud projects add-iam-policy-binding ...               # undo attacker grants found in step 4
```

For widespread compromise, apply an **IAM deny policy** at the folder to freeze permissions such as `iam.googleapis.com/serviceAccountKeys.create` while you clean up ([Policy & governance](policy-governance.md#4-iam-deny-policies)).

## 6. Recover

- Rebuild VMs from known-good images; do not reuse compromised disks.
- Rotate every secret the compromised identity could read ([Secret Manager](keys-secrets.md#4-secret-manager)).
- Delete disabled keys once scoping is complete; block new keys with `iam.disableServiceAccountKeyCreation`.
- Write detections for what you missed ([log-based alerts](monitoring-logs.md#5-log-based-metrics-and-alerts)).

## Related

- [Task: automated containment](../../tasks/incident-response/automated-containment.md)
- [Concept: digital forensics](../../fundamentals/concepts/digital-forensics.md)
- [Task: backup and recovery](../../tasks/administration/backup-and-recovery.md)

## Sources

- [Respond to leaked credentials](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys#respond-to-leaked-credentials)
- [Disable and delete service account keys](https://cloud.google.com/iam/docs/keys-disable-enable)
- [Create disk snapshots](https://cloud.google.com/compute/docs/disks/create-snapshots)
- [Google Cloud incident response guidance](https://cloud.google.com/architecture/security-foundations/detective-controls)
