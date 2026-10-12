---
title: Cloud-Native Security (Containers, Kubernetes, Microservices)
type: concept
platforms: [Linux, Azure]
languages: [Bash, KQL]
tasks: [Hardening, Threat Hunting, Assurance]
category: Cloud Security
security_domain: Cloud
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, containers, kubernetes, docker, cnapp]
aliases: [Cloud Application Security, Cloud Security Tools, Docker Containers, Kubernetes, Microservices Architecture]
difficulty: intermediate
verified: false
---

# Cloud-Native Security (Containers, Kubernetes, Microservices)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** containers and Kubernetes move the attack surface to images, orchestrator permissions and east-west traffic between many small services.

## What it is

**Containers** (Docker, containerd) package an app with its dependencies and share the host kernel — isolation is
weaker than a VM, so a privileged container is close to root on the host. **Kubernetes** schedules containers across a
cluster through an API server; whoever controls that API controls every workload. **Microservices** split an app into
many services talking over the network, multiplying identities, APIs and secrets.

**Cloud security tool categories:**

| Category | Purpose | Examples |
| :--- | :--- | :--- |
| CSPM | misconfiguration of cloud accounts | Defender for Cloud, Prowler, ScoutSuite |
| CWPP | protect workloads (VMs, containers) at runtime | Defender for Containers, Falco |
| CIEM | over-privileged cloud identities | Entra Permissions Management |
| CNAPP | all of the above in one platform | Wiz, Prisma Cloud, Defender for Cloud |
| Image / IaC scanning | vulnerabilities before deploy | Trivy, Checkov, kube-bench |

## How it works

Hardening checklist:

- **Images:** minimal base, scanned in CI, signed, pulled from a private registry; no secrets baked in.
- **Containers:** run as non-root, read-only root filesystem, drop Linux capabilities, never `--privileged`, no
  Docker socket mounts.
- **Kubernetes:** RBAC least privilege (no casual `cluster-admin`), Pod Security Standards `restricted`, network
  policies (default deny), secrets in a vault/KMS, admission control, API server not public, audit logging on.
- **Microservices:** mutual TLS between services (service mesh), API gateway with authentication and rate limits,
  per-service identities.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1610](https://attack.mitre.org/techniques/T1610/) Deploy Container · [T1611](https://attack.mitre.org/techniques/T1611/) Escape to Host · [T1613](https://attack.mitre.org/techniques/T1613/) Container and Resource Discovery · [T1496](https://attack.mitre.org/techniques/T1496/) Resource Hijacking |
| **What it leads to** | cryptomining on exposed clusters, container escape to node, cloud-credential theft from metadata endpoints |
| **Where defenders meet it** | CSPM findings, runtime alerts (shell in container), unexpected pods in `kube-system` |

## Do it

```bash
# What can this identity do in the cluster?
kubectl auth can-i --list
# Who is bound to cluster-admin?
kubectl get clusterrolebindings -o wide | grep cluster-admin
# Pods running privileged
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.containers[*].securityContext.privileged}{"\n"}{end}' | grep true
# Scan an image and the cluster's CIS posture
trivy image nginx:1.27
kube-bench run --targets node
```

```kql
// Defender for Cloud container alerts in the last week
SecurityAlert
| where TimeGenerated > ago(7d) and ProductName has "Containers"
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity
```

## See it

| Source | What you see |
| :--- | :--- |
| Kubernetes audit log | `create pods/exec`, new ClusterRoleBindings, secrets read by unusual service accounts |
| Runtime sensor (Falco, Defender) | shell spawned in a container, writes to `/etc`, mining binaries |
| CSPM | public clusters, privileged pods, registries without scanning |

## Detect it

- Hunt: [Cloud infrastructure ephemeral-asset hunting](../../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md)
- Respond: [Azure resource hijacking](../../tasks/incident-response/azure-resource-hijacking.md)
- Harden: [Azure security baseline](../../tasks/hardening/cloud-azure-security-baseline.md) · [Azure VNet security](../cloud/azure-vnet-security.md)

## Related concepts

- [Secure SDLC and DevSecOps](secure-sdlc-devsecops.md) · [Identity and Access Management](identity-access-management.md) · [ZK, Homomorphic Encryption and Blockchain](zero-knowledge-homomorphic-blockchain.md)
