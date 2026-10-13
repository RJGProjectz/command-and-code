---
title: Google Cloud KMS & Secret Manager
platforms: [GCP]
languages: [Bash, Python]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Secrets
tags: [gcp, cloud kms, cmek, key rotation, key destruction, secret manager, secret versions, cloud hsm, ekm]
aliases: [gcloud kms keys list, gcp rotate kms key, gcloud secrets versions access, gcp secret manager audit, gcp cmek bucket, gcp who accessed secret]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Google Cloud KMS & Secret Manager

**Cloud KMS** holds encryption keys (software, Cloud HSM, or external via EKM) in **key rings** per location. Services use them as **CMEK** to encrypt data you control. **Secret Manager** stores API keys, passwords and certificates as versioned secrets. Both are controlled by IAM on the key or secret.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Commands that change state are marked **change**.

## 1. Inventory keys

```bash
gcloud kms keyrings list --location=<location>
gcloud kms keys list --keyring=<ring> --location=<location> \
  --format="table(name.basename(), purpose, primary.state, protectionLevel:label=LEVEL, rotationPeriod, nextRotationTime)"
gcloud kms keys versions list --key=<key> --keyring=<ring> --location=<location>
gcloud asset search-all-resources --scope=organizations/<ORG_ID> --asset-types=cloudkms.googleapis.com/CryptoKey
```

## 2. Who can use or manage a key

```bash
gcloud kms keys get-iam-policy <key> --keyring=<ring> --location=<location>
```

| Role | Allows |
| :--- | :--- |
| `roles/cloudkms.admin` | Manage keys, **not** use them |
| `roles/cloudkms.cryptoKeyEncrypterDecrypter` | Encrypt and decrypt |
| `roles/cloudkms.cryptoKeyVersionDestroyer` | Schedule destruction |

Keep admin and encrypter/decrypter on different people (separation of duties). Service agents such as `service-<number>@gs-project-accounts.iam.gserviceaccount.com` need encrypter/decrypter for CMEK.

## 3. Rotation and destruction

```bash
# change: rotate every 90 days
gcloud kms keys update <key> --keyring=<ring> --location=<location> \
  --rotation-period=90d --next-rotation-time=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
# change: disable a version (reversible)
gcloud kms keys versions disable <n> --key=<key> --keyring=<ring> --location=<location>
gcloud kms keys versions restore <n> --key=<key> --keyring=<ring> --location=<location>   # undo a scheduled destroy
```

Destroying a version is scheduled (default **30 days**, set per key with `--destroy-scheduled-duration`) and then **permanent**: all data encrypted only with it is lost. Alert on `DestroyCryptoKeyVersion` in audit logs; an attacker who can destroy CMEK keys can make data unreadable.

## 4. Secret Manager

```bash
gcloud secrets list --format="table(name, replication.automatic, createTime, rotation.nextRotationTime)"
gcloud secrets versions list <secret>
gcloud secrets get-iam-policy <secret>
gcloud secrets versions access latest --secret=<secret>      # prints the secret value: avoid in shared terminals
printf '%s' "$NEW_VALUE" | gcloud secrets versions add <secret> --data-file=-   # change
gcloud secrets versions disable <version> --secret=<secret>                    # change
```

Grant `roles/secretmanager.secretAccessor` per secret, not per project. Pin applications to a version number or use `latest` with care.

## 5. Who read a secret?

Secret reads (`AccessSecretVersion`) are **Data Access** logs: enable `DATA_READ` for `secretmanager.googleapis.com` ([Audit logging](audit-logging.md#3-turn-on-data-access-logs)).

```bash
gcloud logging read 'protoPayload.serviceName="secretmanager.googleapis.com"
  AND protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"' \
  --freshness=7d --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.resourceName, protoPayload.requestMetadata.callerIp)"

gcloud logging read 'protoPayload.serviceName="cloudkms.googleapis.com" AND protoPayload.methodName:("Destroy" OR "Disable")' --freshness=30d
```

## 6. Python: read a secret from a workload

```python
from google.cloud import secretmanager   # pip install google-cloud-secret-manager

client = secretmanager.SecretManagerServiceClient()
name = "projects/prod-app-123/secrets/db-password/versions/latest"
value = client.access_secret_version(name=name).payload.data.decode("utf-8")
```

The workload's service account needs `secretAccessor` on that secret only. No key file: ADC picks up the attached service account.

## 7. Find secrets that are not in Secret Manager

- Environment variables in Cloud Run / Cloud Functions: `gcloud run services describe <svc> --format="yaml(spec.template.spec.containers[].env)"`
- VM metadata and startup scripts ([Compute](compute.md#4-service-accounts-and-metadata))
- Service-account JSON keys in buckets and repos ([Storage](storage.md))

## Related

- [Storage → CMEK and retention](storage.md#5-protect-against-deletion-and-ransomware)
- [Incident response](incident-response.md)
- [Detection: CI/CD secret leak](../../detection/sigma/cicd-secret-leak.md)

## Sources

- [Cloud KMS overview](https://cloud.google.com/kms/docs/key-management-service)
- [Key rotation](https://cloud.google.com/kms/docs/key-rotation)
- [Destroy and restore key versions](https://cloud.google.com/kms/docs/destroy-restore)
- [Secret Manager overview](https://cloud.google.com/secret-manager/docs/overview)
