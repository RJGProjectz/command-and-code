---
title: Container & Kubernetes Hardening
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Hardening]
category: Workflow
security_domain: Cloud
author: RJGProjectz
date_created: 2026-10-23
last_updated: 2026-10-23
tags: [kubernetes, k8s, container-hardening, kubelet, kube-apiserver, anonymous-auth, read-only-port, rbac, automountserviceaccounttoken, pod-security, admission-control, networkpolicy, imds, etcd, encryption-at-rest, cis-benchmark, nsa-cisa, supply-chain, defense]
aliases: [kubernetes hardening, harden kubernetes, k8s hardening, kubelet hardening, disable read-only port, kubelet read-only-port 0, kubelet webhook authorization, disable anonymous api server, kubernetes anonymous auth, least privilege rbac kubernetes, automountServiceAccountToken false, pod security admission, deny privileged pods, networkpolicy deny imds, block 169.254.169.254, etcd encryption at rest, cis kubernetes benchmark, nsa cisa kubernetes hardening]
difficulty: advanced
verified: false
---

# Container & Kubernetes Hardening
> **Created**: 2026-10-23T00:00:00Z
> **Last Modified**: 2026-10-23T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands and manifests. Before applying any of them:
> 1. Verify the change and test in a non-production cluster first.
> 2. Ensure you are in a `Test` or `Dev` cluster, not production.
> 3. Validate with `kubectl apply --dry-run=server` / `--dry-run=client` before applying, and audit NetworkPolicy and Pod Security changes in a non-enforcing mode first.
> 4. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The controls below follow the documented behaviour of Kubernetes, the **CIS Kubernetes
    Benchmark** and the **NSA/CISA Kubernetes Hardening Guidance** cited at the foot of this page,
    but have **not** been lab-run end to end for this page. A default-deny `NetworkPolicy`, a
    `restricted` Pod Security level and kubelet/API-server flag changes **can break a working
    cluster** — roll each out in a non-production cluster, watch the audit log and Pod Security
    `warn`/`audit` output, and confirm workloads still run before production. Remove this block when
    `verified: true`.

This is the **defensive counterpart** to
[Enumerate Container and Kubernetes Attack Surface](../../offensive/container-kubernetes-attack-surface.md):
that page maps the reachable, anonymous and over-permissive surface an attacker reads first; this page
closes each finding. Every section below names the offensive section (§1–§7) it hardens. For the model
behind the controls — why a privileged container is "close to root on the host" and why control of the
API server is control of every workload — see
[Cloud-Native Security (Containers, Kubernetes, Microservices)](../../fundamentals/concepts/cloud-native-security.md).

---

## 1. Hardening baseline — principles

Apply these first; the specifics below implement them. They map directly to the CIS Kubernetes
Benchmark sections and the NSA/CISA Kubernetes Hardening Guidance.

| Principle | What it means in practice | Closes (offensive §) |
| :--- | :--- | :--- |
| **No anonymous / read-only surface** | kubelet read-only port off and authz `Webhook`; API server rejects anonymous; runtime API never on `2375`; etcd behind client certs. | §1–§4, §6 |
| **Least privilege** | Scope RBAC to the minimum verbs; no wildcard roles or broad `cluster-admin`; `automountServiceAccountToken: false` where unused. | §5 |
| **Default-deny workloads** | Admission control / Pod Security forbids privileged and host-mounting pods. | §7 |
| **Default-deny network** | NetworkPolicy denies pod egress to the cloud metadata IP (`169.254.169.254`) and isolates namespaces. | §6 |
| **Encrypt at rest & in transit** | etcd Secrets encrypted at rest; TLS between every control-plane component. | §6 |
| **Trusted supply chain** | Pinned, scanned, signed images from an allow-listed registry. | §1–§2 |
| **Audit first** | The control-plane audit log is enabled before anything else — a cluster with auditing off cannot detect any of this. | §4–§5 |

On a **managed cluster** (AKS/EKS/GKE) the control-plane flags in §2–§5 are set by the provider; you
harden them through provider settings instead of static manifests — see §9 and
[Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md).

---

## 2. Kubelet — disable the read-only port, require authentication (closes §3)

The kubelet read-only port (`10255`) serves `/pods`, `/metrics` and `/spec` **unauthenticated** — pure
disclosure. The full kubelet API (`10250`) must require authentication and authorization, not
`AlwaysAllow`. Set this in the kubelet config file (`/var/lib/kubelet/config.yaml`) on every node —
**CIS Kubernetes Benchmark §4.2**:

```yaml
# /var/lib/kubelet/config.yaml  — per node. Restart the kubelet after editing.
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
readOnlyPort: 0                 # CIS 4.2 — disable the unauthenticated read-only port (10255)
authentication:
  anonymous:
    enabled: false             # CIS 4.2 — no anonymous requests to the kubelet API (10250)
  webhook:
    enabled: true              # delegate authn to the API server (TokenReview)
authorization:
  mode: Webhook                # CIS 4.2 — NOT AlwaysAllow; delegate authz to the API server (SubjectAccessReview)
```

```bash
# Apply on the node, then restart and confirm the read-only port is gone.
sudo systemctl restart kubelet
# Expect: no listener on 10255 (connection refused), 10250 answers 401 to an unauthenticated GET.
ss -lntp | grep -E ':10250|:10255' || echo "read-only port 10255 not listening — good"
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:10250/pods    # expect 401
```

> On kubeadm clusters the `KubeletConfiguration` is distributed via the `kubelet-config` ConfigMap in
> `kube-system`; edit it there and re-roll nodes rather than drifting each node by hand.

---

## 3. API server — reject anonymous, restrict reachability (closes §4)

A `200` to an anonymous listing on the API server is an over-permissive finding. Keep
`system:anonymous` / `system:unauthenticated` and the broad `system:authenticated` group unbound from
anything useful, and do not run the API server with anonymous auth on — **CIS Kubernetes Benchmark
§1.2**:

```yaml
# kube-apiserver manifest flags (/etc/kubernetes/manifests/kube-apiserver.yaml on kubeadm nodes)
- --anonymous-auth=false            # CIS 1.2 — reject unauthenticated requests
- --authorization-mode=Node,RBAC    # CIS 1.2 — NOT AlwaysAllow; Node + RBAC only
```

Audit who is bound to the built-in groups and remove anything over-broad:

```bash
# Nothing useful should be granted to anonymous / all-authenticated identities.
kubectl get clusterrolebindings,rolebindings -A -o json | jq -r '
  .items[]
  | select(.subjects[]? | .name=="system:anonymous" or .name=="system:unauthenticated"
           or .name=="system:authenticated")
  | (.kind + " " + (.metadata.namespace // "cluster") + "/" + .metadata.name
     + " -> " + .roleRef.name)'
```

**Restrict who can even reach the API server.** The API endpoint should not be open to the whole
internet: put it behind authorized IP ranges / a private endpoint or a firewall + network policy. This
is a provider setting on managed clusters — on AKS use API-server **authorized IP ranges** or a private
cluster ([AKS §1 security settings](../../platforms/azure/kubernetes.md)); self-managed, front it with a
default-deny firewall that allows only the admin network and nodes.

---

## 4. Container runtime API — never expose it (closes §1–§2)

The Docker/`containerd` runtime API on TCP `2375` (plaintext) is **remote root on the host** — a
`GET /version` or `/containers/json` that answers unauthenticated is the whole node. It must never
listen on a network interface.

```bash
# The daemon should bind only the local unix socket, never tcp://0.0.0.0:2375.
ss -lntp | grep ':2375' && echo "DANGER: runtime API on the network — close it" || echo "2375 not listening — good"

# Docker daemon: ensure no insecure tcp host is configured.
sudo grep -R -- '-H tcp://' /etc/systemd/system/docker.service.d/ /etc/docker/daemon.json 2>/dev/null \
  && echo "remove the tcp:// host" || echo "no tcp host configured — good"
```

If remote Docker access is genuinely required, use the TLS-protected port `2376` with
`--tlsverify` and client certs — never the plaintext `2375`. Prefer not exposing it at all and using
`kubectl` / the Kubernetes API for all container operations.

---

## 5. etcd — client-cert auth and encryption at rest for Secrets (closes §6)

etcd holds every object in the cluster, including Secrets, in the clear unless you encrypt them.
A reachable, unauthenticated etcd is the whole cluster. Require mutual TLS on etcd and enable
**encryption at rest** for Secrets on the API server — **CIS Kubernetes Benchmark §2 and §1.2**:

```yaml
# etcd flags — require client certificates, no auto-TLS. (CIS §2)
- --client-cert-auth=true
- --auto-tls=false
- --peer-client-cert-auth=true
- --peer-auto-tls=false
```

```yaml
# EncryptionConfiguration referenced by the API server's --encryption-provider-config flag.
# Encrypts Secrets at rest in etcd (CIS §1.2). Use a KMS provider in production rather than a local key.
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:                        # prefer a `kms:` provider (external KMS) in production
          keys:
            - name: key1
              secret: <base64-32-byte-key>   # store/rotate via a KMS, never commit this
      - identity: {}                   # fallback for reads of not-yet-encrypted data
```

```bash
# After enabling, rewrite existing Secrets so they are encrypted on disk.
kubectl get secrets -A -o json | kubectl replace -f -
```

> On managed clusters etcd is operated by the provider and is already encrypted and mutually
> authenticated — you do not set these flags; confirm the provider's Secret-encryption option (e.g.
> KMS etcd encryption) is enabled instead.

---

## 6. Least-privilege RBAC (closes §5)

`kubectl auth can-i --list` on the offensive page is the before/after evidence here: after hardening,
`system:anonymous` and unused service accounts should be able to do nothing useful. **CIS Kubernetes
Benchmark §5.1.**

```bash
# Find wildcard roles — a Role/ClusterRole granting "*" verbs or resources is rarely justified. (CIS 5.1.3)
kubectl get clusterroles,roles -A -o json | jq -r '
  .items[]
  | select((.rules[]?.verbs[]? == "*") or (.rules[]?.resources[]? == "*"))
  | .kind + " " + (.metadata.namespace // "cluster") + "/" + .metadata.name'

# Who holds cluster-admin? Each binding must be a named, justified human/automation identity. (CIS 5.1.1)
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | select(.roleRef.name=="cluster-admin")
  | .metadata.name + " -> " + ([.subjects[]? | .kind + ":" + .name] | join(", "))'
```

Turn off service-account token automounting for workloads that never call the API — a pod with no
mounted token cannot have its token stolen and replayed (offensive §6). **CIS 5.1.5–5.1.6.**

```yaml
# Per ServiceAccount (preferred) — no token is mounted unless a pod opts back in.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-frontend
  namespace: prod
automountServiceAccountToken: false
---
# ...or per Pod spec, for a workload that must stay on a token-bearing SA for other reasons:
# spec:
#   automountServiceAccountToken: false
```

Scope every Role to the minimum verbs and resources; bind with `RoleBinding` (namespaced) in
preference to `ClusterRoleBinding`. Avoid granting `create`/`update` on `pods`, `rolebindings`,
`clusterrolebindings` or `secrets` to workload identities — those are exactly the escape/escalation
preconditions §5 and §7 report.

---

## 7. Admission control / Pod Security — forbid privileged & host-mounting pods (closes §7)

A privileged or host-mounting pod is one `kubectl apply` away from node compromise. The built-in **Pod
Security Admission** controller enforces the `restricted` Pod Security Standard, which forbids
`privileged`, `hostPID`/`hostIPC`/`hostNetwork`, host-path mounts, privilege escalation and running as
root. **CIS Kubernetes Benchmark §5.2 / NSA/CISA "Pod Security".**

```yaml
# Enforce the restricted standard at the namespace. Start with warn/audit, then enforce.
apiVersion: v1
kind: Namespace
metadata:
  name: prod
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted     # surface violations to kubectl users first
    pod-security.kubernetes.io/audit: restricted     # and to the audit log
```

```bash
# Dry-run the label against existing workloads to see what WOULD be rejected before you enforce.
kubectl label --dry-run=server --overwrite ns prod pod-security.kubernetes.io/enforce=restricted

# Inventory the pods that today violate it — the privileged / host-mounting ones from offensive §3.
kubectl get pods -A -o json | jq -r '
  .items[]
  | select((.spec.containers[].securityContext.privileged==true)
           or .spec.hostNetwork==true or .spec.hostPID==true or .spec.hostIPC==true)
  | .metadata.namespace + "/" + .metadata.name'
```

For policy beyond the three built-in levels (registry allow-lists, required `runAsNonRoot`, dropped
capabilities, blocked host-paths), use a policy engine — **Kyverno** or **OPA Gatekeeper** — as a
validating admission webhook. Keep the webhook `failurePolicy: Fail` for security policies so a
down webhook does not silently admit everything.

---

## 8. NetworkPolicy — deny egress to cloud metadata and isolate namespaces (closes §6)

The cloud metadata endpoint (`169.254.169.254`, IMDS) is the pivot from a pod to the node's cloud
identity (offensive §6). A default-deny egress policy that excludes the link-local metadata range
closes it. **CIS Kubernetes Benchmark §5.3 / NSA/CISA "Network separation and hardening".**

```yaml
# Default-deny all egress in the namespace, then allow only what workloads need (DNS + in-cluster).
# The 169.254.0.0/16 link-local range (incl. 169.254.169.254 IMDS) is excluded from every allow rule.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress-and-block-imds
  namespace: prod
spec:
  podSelector: {}                 # all pods in the namespace
  policyTypes: [Egress]
  egress:
    - to:                         # allow cluster-internal + public, but NOT link-local metadata
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.0.0/16    # blocks the IMDS pivot (169.254.169.254) and other link-local
    - to:                         # DNS to kube-dns
        - namespaceSelector: {}
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
```

```bash
# A namespace with zero NetworkPolicies allows all pod traffic (CIS 5.3.2) — list the gaps.
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  n=$(kubectl get netpol -n "$ns" --no-headers 2>/dev/null | wc -l)
  [ "$n" -eq 0 ] && echo "NO NetworkPolicy: $ns"
done
```

> NetworkPolicy is enforced only by a CNI that supports it (Calico, Cilium, etc.). On a CNI that
> ignores policy, these objects apply cleanly but block nothing — confirm enforcement in a test
> namespace. Pods using `hostNetwork` bypass NetworkPolicy, which is a further reason §7 forbids them.

---

## 9. Image & supply-chain basics (closes §1–§2)

Most of the attack surface above is a container someone could run; control what runs:

- **Pin and scan.** Pin images by digest (`@sha256:…`), not `:latest`; scan them for known CVEs in CI
  and block on critical findings — see
  [Vulnerability Assessment & Patch Management](../../fundamentals/concepts/vulnerability-management.md).
- **Allow-list registries.** Admit images only from your own registry/namespaces (a Kyverno/Gatekeeper
  rule, or the provider's registry allow-list), so a typo-squatted or public image cannot be scheduled.
- **Sign and verify.** Sign images (Sigstore/`cosign`) and require a valid signature at admission.
- **Minimal base + non-root.** Distroless/minimal base images and `runAsNonRoot: true` with dropped
  capabilities shrink what a foothold can do — these are also enforced by §7's `restricted` level.
- **Protect the pipeline.** A leaked kubeconfig or registry credential from CI is a direct path in
  (offensive §6) — keep build secrets out of logs:
  [Sigma — CI/CD Secret Leak in Build Logs](../../detection/sigma/cicd-secret-leak.md).

---

## 10. Managed-cluster baseline (AKS)

On AKS the control-plane flags in §2–§5 are the provider's; you harden them through AKS settings:
disable local accounts in favour of Entra RBAC, restrict the API server with authorized IP ranges or a
private cluster, enable workload identity so pods get federated tokens instead of stored secrets, and
turn on audit logging. The settings, their secure values and why each matters are on
[Azure Kubernetes Service (AKS)](../../platforms/azure/kubernetes.md) §1, and the surrounding tenant
controls on [Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md).

---

## Detect it

Hardening reduces the attack surface; the control-plane audit log catches what still gets tried —
**enable it first** (a cluster with auditing off cannot detect any of this).

- **Anonymous / over-permissive API calls, RBAC probing, exec-into-pod, Secret reads, RBAC changes** →
  the Kubernetes audit log. On AKS, query the `kube-audit` / `kube-audit-admin` categories in KQL:
  [Azure Kubernetes Service (AKS)](../../platforms/azure/kubernetes.md#5-audit-logs). A dedicated,
  vendor-neutral Kubernetes-audit SPL/KQL/Sigma page is **not published on the
  [Detection](../../detection/index.md) tab yet** — until it is, the AKS audit-log guidance is the
  closest query-level reference.
- **Stolen kubeconfig / service-account token from a pipeline** →
  [Sigma — CI/CD Secret Leak in Build Logs](../../detection/sigma/cicd-secret-leak.md).
- **Anomalous workload/identity activity across cloud-native infra** →
  [Cloud infrastructure ephemeral-asset hunting](../threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md);
  respond with [Azure resource hijacking](../incident-response/azure-resource-hijacking.md).
- **Unauthenticated runtime (§4) and read-only kubelet (§2) probes may leave no application log at
  all** — which is exactly why §4/§8's network-level controls, not logging, are the primary defence
  there.

---

## Related

- **Offensive counterpart:** [Enumerate Container and Kubernetes Attack Surface](../../offensive/container-kubernetes-attack-surface.md) — every finding there maps to a control here (§1–§7 ↔ this page's §2–§8)
- Reference: [Cloud-Native Security (Containers, Kubernetes, Microservices)](../../fundamentals/concepts/cloud-native-security.md) — the model behind these controls (CWPP, admission control, network policy)
- [Azure Kubernetes Service (AKS)](../../platforms/azure/kubernetes.md) — managed-cluster settings + `kube-audit` KQL · [Azure & Entra ID Security Baseline](cloud-azure-security-baseline.md) — the surrounding tenant baseline
- [Linux CIS — Access Control, PAM & SSH](linux-cis-access-pam-ssh.md) · [Per-Service Egress Control](per-service-egress-control.md) — the host and egress layers beneath the cluster
- [Vulnerability Assessment & Patch Management](../../fundamentals/concepts/vulnerability-management.md) · [Identity and Access Management](../../fundamentals/concepts/identity-access-management.md)
- [CIS Benchmarks & Critical Controls](../../fundamentals/grc/cis-benchmarks.md) · [Cyber Law & Authorization](../../fundamentals/concepts/cyber-law.md)

## External Resources & White Papers

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — the node, API server, etcd, kubelet, RBAC, Pod Security and NetworkPolicy settings this page applies
- [NSA/CISA — Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) — the authoritative control mapping behind this page
- [Kubernetes — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) · [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes — Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) · [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubelet configuration (v1beta1)](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/) · [Controlling Access to the Kubernetes API](https://kubernetes.io/docs/concepts/security/controlling-access/)
