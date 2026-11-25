---
title: Secrets Management
type: concept
platforms: [Linux, Windows, AWS, Azure, GCP, GitHub]
languages: [Bash, PowerShell, Python]
tasks: [Hardening, Administration, Assurance]
category: Secrets and Credentials
security_domain: Cloud
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, secrets-management, vault, api-key, credentials, devsecops, cloud-security]
aliases: [secrets management, vault, secrets store, API key management, service credentials, Hashicorp Vault, AWS Secrets Manager, Azure Key Vault]
difficulty: intermediate
verified: false
---

# Secrets Management
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** the discipline of storing, distributing, rotating, and auditing non-human credentials — API keys, database passwords, TLS certificates, and service tokens — so workloads get secrets dynamically rather than from hard-coded files or environment variables.

## What it is

Non-human identities need secrets just as human users need passwords: a container must authenticate to a database, a CI pipeline must push to an artifact registry, and a serverless function must call a third-party API. When those secrets are hard-coded in source code, committed to version control, or baked into container images, any person or automated scanner who reads the repository or image also reads the credentials. The 2017 Uber breach and many subsequent high-profile incidents traced directly to credentials exposed in code.

Secrets management solves this by moving secrets out of application code and into a dedicated, access-controlled store. The application calls the secrets manager at runtime to retrieve only the credentials it needs, with the minimum necessary permissions, for the minimum necessary duration. Modern secrets managers also automate rotation — periodically replacing a credential before it can be harvested — and emit an audit log of every secret access, so security teams can detect anomalies.

Cloud providers offer native secrets stores: AWS Secrets Manager, Azure Key Vault, and GCP Secret Manager. HashiCorp Vault is a popular open-source option that works across any infrastructure. Kubernetes-native solutions such as the Kubernetes Secrets Store CSI Driver integrate vault backends with Pod-mounted secret volumes.

## How it works

```text
Application at runtime
  │
  ├─ authenticates to Vault / Secrets Manager
  │      using: IAM role, service account token, AppRole, or mTLS cert
  │
  ├─ requests secret: "db/prod/password"
  │      Vault checks policy: does this identity have read on this path?
  │
  ├─ receives dynamic credential (or static secret)
  │      dynamic: Vault generates a new DB user/password, TTL 1 hour
  │      static: returns stored value with lease
  │
  └─ uses credential → expires / auto-renewed by agent
         ▲
         └─ rotation job periodically regenerates static secrets
```

A well-architected secrets pipeline has four properties: **centralisation** (one authoritative store, not scattered env files), **least privilege** (each workload can read only its own secrets), **rotation** (secrets change before attackers can exploit a leaked copy), and **auditability** (every read and write is logged with the caller's identity).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) — Credentials in Files · [T1552.004](https://attack.mitre.org/techniques/T1552/004/) — Private Keys |
| **What it leads to** | long-lived, hard-coded secrets are a persistent backdoor; a single git repository clone or image pull gives an attacker full service credentials |
| **Where defenders meet it** | secret-scanning alerts in CI/CD, anomalous API calls from credentials that should be idle, leaked AWS access keys in public repos |

## Do it

```bash
cc find "secrets vault"
cc view docs/fundamentals/concepts/secure-sdlc-devsecops.md
cc view docs/tasks/hardening/index.md
```

Scan a local codebase for accidentally committed secrets on a machine you own:

```bash
# Detect common secret patterns with git-secrets or trufflehog (run on your own repo)
# Install: pip install trufflehog
trufflehog filesystem --directory . --only-verified
```

```powershell
# Check for secrets in environment variables on a Windows host you own
Get-ChildItem Env: | Where-Object {
  $_.Value -match '(?i)(password|secret|token|key|apikey)' -and $_.Value.Length -gt 8
} | Select-Object Name, @{ N='Value'; E={'[REDACTED]' } }
```

!!! caution "SAFETY WARNING: VALIDATE BEFORE EXECUTION"
    The commands above run on systems you own for security auditing. Do not scan repositories or systems without written authorisation. Treat any discovered secrets as compromised immediately — rotate them before investigating further.

## See it

Secrets management failures surface in multiple ways, depending on where the secret was exposed:

| Source | What you see |
| :--- | :--- |
| GitHub / GitLab secret scanning | Alert on detected high-entropy string or matched pattern (AWS key, PEM header) in a commit or PR |
| Cloud provider credential logs | API calls from a credential that is associated with a build server but originating from an external IP |
| Vault audit log | Unexpected read of a secret path by an identity that has not previously accessed it |
| SIEM / alert | Multiple failed `GetSecretValue` calls followed by a successful one from an unusual source — possible credential stuffing against the secrets API |
| Container image scan | Secret found embedded in a Docker layer (even if the layer is overwritten, all layers are present in the image) |

## Detect it

- Detection: [Detection Engineering](../../tasks/detection-engineering/index.md)
- Hunt: [Threat Hunting Workflows](../../tasks/threat-hunting/index.md)
- Respond: [Incident Response](../../tasks/incident-response/index.md)
- Harden: [Hardening Tasks](../../tasks/hardening/index.md)

## Best-practice controls

| Control | Why it helps |
| :--- | :--- |
| Central secrets store (Vault, AWS SM, Key Vault) | Removes secrets from code, configs, and images; enables centralised access control and rotation |
| Short-lived dynamic credentials | A credential that expires in hours is worthless if stolen days after the breach |
| Automated rotation | Eliminates long-lived static credentials that accumulate risk over their lifetime |
| Secret scanning in CI/CD | Blocks secrets from reaching version control in the first place |
| Least-privilege IAM bindings | Each service role can read only its own secret paths — a compromised workload cannot pivot to other services |
| Audit logging and alerting | Unusual access patterns to the secrets store trigger before the credential is abused at scale |

## Related concepts

- [Secure SDLC, DevSecOps and Secure Coding](secure-sdlc-devsecops.md)
- [Identity and Access Management](identity-access-management.md)
- [Credential Stuffing](credential-stuffing.md)
- [Credential Dumping](credential-dumping.md)
