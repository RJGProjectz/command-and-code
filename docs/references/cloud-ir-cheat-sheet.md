---
title: Cloud Incident Response Cheat Sheet (Printable)
type: reference
platforms: [AWS, Azure, GCP]
languages: [Bash, PowerShell]
tasks: [Incident Response, Investigation, Forensics]
category: Reference
tags: [cloud, incident response, cheat sheet, printable, aws, azure, gcp, containment]
aliases: [cloud ir cheat sheet, cloud incident response commands, aws ir cheat sheet, azure ir cheat sheet, gcp ir cheat sheet]
difficulty: advanced
verified: true
last_verified: 2026-10-13
search:
  boost: 3
---

# Cloud Incident Response Cheat Sheet (Printable)

The first hour of a cloud compromise on AWS, Azure and GCP: check who you are, contain the identity, isolate the VM,
preserve evidence, scope. The **Print** button gives one landscape sheet, printed on both sides.

!!! warning "Before you run anything"
    Every command is taken from this site's AWS, Azure and GCP incident-response pages, which were checked against the
    vendor CLI references (2026-10-12); this guide does not run them against a live account. Nearly all of them are
    **change** commands. Record what you change, and disable rather than delete until the scope is known.

## 1. First minute: who am I, where am I

```bash
aws sts get-caller-identity
az account show --query "{tenant:tenantId, sub:id, user:user.name, type:user.type}"
gcloud auth list
```

Wrong account or subscription is the most common IR mistake. Open a case log with UTC timestamps before the first change.

## 2. AWS: contain the identity

```bash
aws iam list-access-keys --user-name <user>
aws iam update-access-key --user-name <user> --access-key-id <AKIA_KEY_ID> --status Inactive
aws iam delete-login-profile --user-name <user>          # removes the console password
# stolen role session: deny every token issued before now
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name <role> --policy-name AWSRevokeOlderSessions --policy-document "{
  \"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",
  \"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"$now\"}}}]}"
```

## 3. AWS: isolate, preserve, scope

```bash
aws ec2 modify-instance-attribute --instance-id <id> --groups <quarantine-sg-id>   # SG with no rules
aws ec2 modify-instance-attribute --instance-id <id> --disable-api-termination
aws ec2 create-snapshot --volume-id <vol-id> --description "IR <case> from <id>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<AKIA_KEY_ID>
```

Security-group changes do not cut **tracked** connections: add a deny-all network ACL too.
Full steps: [AWS incident response](../platforms/aws/incident-response.md).

## 4. Azure: contain the identity

```powershell
Connect-MgGraph -Scopes 'User.ReadWrite.All'
Update-MgUser -UserId <upn> -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId <upn>                 # invalidates refresh tokens
```

```bash
az ad sp update --id <app-id> --set accountEnabled=false
az ad app credential list --id <app-id> -o table          # attacker-added secrets and certificates
az role assignment list --assignee <principal-id> --all -o table
```

## 5. Azure: isolate, preserve, scope

```bash
az network nic update -g <rg> -n <nic> --network-security-group nsg-quarantine   # deny-all NSG
az snapshot create -g <ir-rg> -n ir-<case>-<disk> --source <disk-id> --network-access-policy DenyAll
```

```bash
# everything the principal did (Activity Log, up to 90 days; default is only 50 events)
az monitor activity-log list --caller <upn> --offset 30d --max-events 1000 \
  --query "[].{time:eventTimestamp, op:operationName.value, status:status.value, rg:resourceGroupName}" -o table
```

For longer history or many principals, query `AzureActivity` in Log Analytics instead.
Full steps: [Azure incident response](../platforms/azure/incident-response.md).

## 6. GCP: contain the identity

```bash
SA=<sa>@<PROJECT_ID>.iam.gserviceaccount.com
gcloud iam service-accounts keys list --iam-account=$SA --managed-by=user
gcloud iam service-accounts keys disable <KEY_ID> --iam-account=$SA
gcloud iam service-accounts disable $SA                  # stops every workload using it
gcloud iam service-accounts get-iam-policy $SA           # who can impersonate it
```

## 7. GCP: isolate, preserve, scope

```bash
gcloud compute instances add-tags <vm> --zone=<zone> --tags=quarantine    # deny-all rules target this tag
gcloud compute snapshots create ir-<disk> --source-disk=<disk> --source-disk-zone=<zone> --labels=case=<case-id>
gcloud logging read "protoPayload.authenticationInfo.principalEmail=\"$SA\"" --organization=<ORG_ID> --freshness=30d \
  --format="table(timestamp, resource.labels.project_id, protoPayload.methodName, protoPayload.requestMetadata.callerIp)"
```

Create the two `quarantine` deny-all firewall rules first. Full steps: [GCP incident response](../platforms/gcp/incident-response.md).

## 8. Order of operations

- **Identity:** disable keys and sessions, then hunt for new ones. Don't delete the user: you lose searches by key ID.
- **Compute:** isolate the network and keep it running for memory. Don't stop it before snapshot and memory capture.
- **Evidence:** snapshot disks and export logs to a locked account. Don't analyse in the compromised account.
- **Scope:** everything the identity did in 30 days, in every region and project. Don't stop at the first one.
- **Recover:** rebuild from known-good images. Don't clean in place.

## Sources

- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Revoking IAM role temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [Microsoft Learn — Revoke user access in an emergency](https://learn.microsoft.com/entra/identity/users/users-revoke-access)
- [Google Cloud — Data incident response process](https://cloud.google.com/docs/security/incident-response)
