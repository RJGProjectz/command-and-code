---
title: Google Cloud CLI, SDKs & Authentication
platforms: [GCP]
languages: [Bash, PowerShell, Python]
tasks: [Administration, Automation, Incident Response]
category: Authentication
tags: [gcp, gcloud, application default credentials, adc, service account impersonation, workload identity federation, metadata server, google-auth]
aliases: [gcloud auth login, gcloud auth list, gcloud config configurations, gcloud impersonate service account, application default credentials, gcp metadata server token]
difficulty: basic
verified: true
last_verified: 2026-10-12
---

# Google Cloud CLI, SDKs & Authentication

Google Cloud has **two credential stores** on a workstation, and mixing them up is the most common confusion:

| Store | Set by | Used by |
| :--- | :--- | :--- |
| **gcloud credentials** | `gcloud auth login` | `gcloud`, `gcloud storage`, `bq` |
| **Application Default Credentials (ADC)** | `gcloud auth application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, or the metadata server | Client libraries (Python, Go, Terraform provider) |

Prefer user accounts plus **service-account impersonation** over downloaded service-account keys.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Run read-only commands first. Commands that change state are marked **change**.

## 1. Install and check the tools

```bash
gcloud version                         # Google Cloud SDK, bq, gsutil, core
gcloud components update               # not available when installed through apt/yum; use the package manager
pip install google-cloud-storage google-auth
```

On Windows, install the Google Cloud CLI installer; `gcloud` works the same in PowerShell.

## 2. Sign in

| Identity | How |
| :--- | :--- |
| Human user | `gcloud auth login` (browser), then `gcloud auth application-default login` if local code needs ADC |
| Admin task with least privilege | Stay signed in as yourself; add `--impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com` |
| Compute Engine, GKE, Cloud Run workload | Attached service account; tokens come from the metadata server |
| CI/CD outside Google Cloud | **Workload Identity Federation** (OIDC/SAML/AWS), no stored keys |
| Service-account JSON key | Last resort; block creation with the Org Policy `iam.disableServiceAccountKeyCreation` |

```bash
gcloud config configurations create prod-ir
gcloud config set account analyst@example.com
gcloud config set project prod-app-123
gcloud config set compute/region northamerica-northeast1
gcloud config configurations activate prod-ir      # or: --configuration=prod-ir per command
```

## 3. Who am I?

```bash
gcloud auth list                                   # active account marked with *
gcloud config list                                 # account, project, region of the active configuration
gcloud auth print-access-token | head -c 20; echo  # proves the token works without printing all of it
curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=$(gcloud auth print-access-token)"
```

```python
import google.auth
creds, project = google.auth.default()
print(type(creds).__name__, project, getattr(creds, "service_account_email", "user"))
```

## 4. Impersonate a service account

```bash
gcloud compute instances list --impersonate-service-account=ir-reader@sec-tools.iam.gserviceaccount.com
gcloud config set auth/impersonate_service_account ir-reader@sec-tools.iam.gserviceaccount.com   # change: all commands
gcloud config unset auth/impersonate_service_account
gcloud auth application-default login --impersonate-service-account=ir-reader@sec-tools.iam.gserviceaccount.com
```

You need `roles/iam.serviceAccountTokenCreator` **on that service account**. Cloud Audit Logs record both identities: the caller in `protoPayload.authenticationInfo.principalEmail` and the chain in `serviceAccountDelegationInfo`.

## 5. Credential resolution order (ADC)

Client libraries stop at the first source that works:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable (path to a key or external-account file)
2. The ADC file from `gcloud auth application-default login`
3. The attached service account, through the metadata server

`gcloud` itself ignores ADC and uses its own active account, unless `auth/credential_file_override` is set. A leftover `GOOGLE_APPLICATION_CREDENTIALS` pointing to an old key is the usual reason code runs as the wrong identity.

## 6. Metadata server

On Compute Engine, GKE and Cloud Run, the attached service account's token comes from the metadata server. Every request needs the `Metadata-Flavor: Google` header, which blocks simple SSRF.

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

Access scopes still limit what a VM's token can do; the IAM roles of the service account are the real control ([Compute](compute.md#4-service-accounts-and-metadata)).

## 7. Known locations

| Path | Contents |
| :--- | :--- |
| `~/.config/gcloud/` (`%APPDATA%\gcloud\`) | Configurations, `credentials.db`, `access_tokens.db` |
| `~/.config/gcloud/application_default_credentials.json` | ADC refresh token for the user |
| `~/.config/gcloud/legacy_credentials/` | Per-account credential files (older SDK layout) |
| Any `*.json` with `"type": "service_account"` | Downloaded service-account private key |

Treat all of these as credentials. On a compromised workstation, collect them as evidence and then [revoke the tokens and keys](incident-response.md#1-contain-the-identity).

## Related

- [Identity & access (Cloud IAM)](identity-access.md)
- [Troubleshooting → Permission denied](troubleshooting.md#1-permission-denied-and-authentication-errors)
- [Concept: authentication and MFA](../../fundamentals/concepts/authentication-mfa-sso.md)

## Sources

- [Authorize the gcloud CLI](https://cloud.google.com/sdk/docs/authorizing)
- [How Application Default Credentials works](https://cloud.google.com/docs/authentication/application-default-credentials)
- [Use service account impersonation](https://cloud.google.com/docs/authentication/use-service-account-impersonation)
- [About VM metadata](https://cloud.google.com/compute/docs/metadata/overview)
