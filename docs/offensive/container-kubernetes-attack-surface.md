---
title: Enumerate Container and Kubernetes Attack Surface — Exposed Runtimes, kubelet, API Server and RBAC
type: workflow
platforms: [Linux]
languages: [Bash, Python]
tasks: [Assessment]
category: Workflow
security_domain: Cloud
author: RJGProjectz
date_created: 2026-10-23
last_updated: 2026-10-23
tags: [containers, kubernetes, k8s, docker, container-runtime, kubelet, kube-apiserver, anonymous-auth, rbac, kubectl, service-account, service-account-token, kubernetes-dashboard, etcd, imds, cloud-metadata, container-escape, attack-surface, enumeration, parrot-os, kali]
aliases: [container attack surface, kubernetes attack surface, k8s enumeration, kubelet enumeration, exposed docker api, anonymous kubernetes api, kubectl auth can-i, rbac enumeration, service account token, kubernetes dashboard exposed, exposed etcd, pod metadata ssrf, container escape awareness, enumerate kubernetes cluster, assess kubernetes posture]
difficulty: intermediate
verified: false
---

# Enumerate Container and Kubernetes Attack Surface — Exposed Runtimes, kubelet, API Server and RBAC
> **Created**: 2026-10-23T00:00:00Z
> **Last Modified**: 2026-10-23T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> A container platform usually runs production workloads for many tenants on shared infrastructure —
> enumeration here touches a live control plane, so apply the same discipline as any production change.
> 1. Enumerate **only** the clusters, nodes, registries and cloud projects named in a signed engagement
>    or in your own lab. A single over-broad query against the Kubernetes API server is logged against
>    your service account and can trip rate limits or admission webhooks on a production cluster.
> 2. **Discovery, not takeover.** This page maps *reachable* attack surface — exposed runtime APIs,
>    kubelet, anonymous/over-permissive API access, RBAC you already hold, discoverable tokens and
>    dashboards. Actually **abusing** a token, **escaping** a container or **escalating** to
>    cluster-admin is weaponized post-exploitation and is documented here as **awareness + detect/harden
>    only** (§7), never as working tooling.
> 3. Service-account tokens, kubeconfigs and registry credentials you discover are **live secrets** —
>    store them with the engagement evidence, never paste them into the report or a chat, and handle them
>    under [Cyber Law](../fundamentals/concepts/cyber-law.md) and
>    [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (`kubectl`, `curl`, `nmap`, `jq`; Parrot OS
    / Kali packages) but have not been lab-run for this page. Ports, API paths, flags and RBAC behaviour
    vary by Kubernetes version, distribution (vanilla, AKS/EKS/GKE, k3s, OpenShift) and runtime — confirm
    each path against the cluster's version and against `kubectl --help` / the Kubernetes API reference
    before you run it in scope. Remove this block when `verified: true`.

**Trigger:** an authorized engagement has reached **Stage 1 (Reconnaissance)** and the estate includes
containers or a Kubernetes cluster — you have landed on a network segment that can reach a container host
or control plane, or you hold a (possibly low-privilege) foothold **inside** a pod and need to map what
that position can reach.

**Goal:** produce an evidenced map of the **container and Kubernetes attack surface** — which runtime and
control-plane endpoints are reachable, whether any accept anonymous or over-permissive access, what your
current identity is authorized to do, and which tokens, dashboards and cloud-metadata endpoints are within
reach — **without** abusing any of them. This page is part of Stage 1 (Reconnaissance) of the
[red-team lifecycle](index.md) and sits alongside
[Cloud Attack Surface Enumeration](cloud-attack-surface-enumeration.md) (the IaaS/identity layer beneath
the cluster). For the underlying theory and the defender's model, see
[Cloud-Native Security (Containers, Kubernetes, Microservices)](../fundamentals/concepts/cloud-native-security.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Scope & vantage (§0) | engagement docs | Which clusters/nodes/registries are in scope; where you are (external, node LAN, inside a pod) |
| Reachable endpoints (§1) | `nmap`, `curl` | Which container/control-plane ports answer (2375/2376, 10250/10255, 6443, 2379, dashboards) |
| Container runtime API (§2) | `curl`, `docker` | Whether an unauthenticated Docker/containerd API is exposed |
| kubelet surface (§3) | `curl` | What the read-only (10255) and authenticated (10250) kubelet leak |
| API server & auth (§4) | `kubectl`, `curl` | Whether the API server allows anonymous access; the server version |
| Identity & RBAC (§5) | `kubectl auth can-i`, `kubectl get` | What *your* identity can do — the single most important question |
| Tokens, dashboards, etcd, metadata (§6) | `kubectl`, `curl`, Python | Discoverable service-account tokens, exposed dashboard/etcd, pod→cloud-metadata reachability |
| *Escape / escalation (know-it only)* (§7) | *theory — no tooling* | *How a foothold becomes host/cluster compromise — for detect/harden, not run here* |

## 0. Set the scope and know your vantage point

```bash
# In-scope ONLY — fill from the engagement. Enumeration is logged against your identity.
CLUSTER_API="https://k8s-api.corp.example:6443"   # authorized API server, if known
NODE="10.0.5.21"                                    # an in-scope node / container host
OUT="./k8s_surface_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
```

Your **vantage point** decides which sections apply — record it first:

- **External / node LAN:** you can reach node and control-plane *ports* but hold no cluster identity yet
  → §1–§4 (what answers, what is anonymous).
- **Inside a pod:** you have a shell in a container (e.g. via a web app foothold) and an *in-cluster*
  service-account identity → §3 (node-local kubelet), §5 (what the mounted token can do), §6 (token,
  metadata) matter most.

## 1. Which endpoints are reachable

Container platforms expose a predictable set of ports. A scoped, rate-limited scan tells you which answer
before you touch any of them:

```bash
# Scoped TCP scan of the classic container/K8s ports. Stay in scope and under any agreed rate.
nmap -Pn -p 2375,2376,2379,2380,4194,6443,8080,8443,10250,10255,10256,30000-32767 \
  -oA "$OUT/portscan" "$NODE"
```

| Port(s) | Service | Why it matters |
| :--- | :--- | :--- |
| 2375 / 2376 | Docker Engine API (plain / TLS) | 2375 is **unauthenticated** — full control of the daemon if reachable |
| 2379 / 2380 | etcd client / peer | the cluster's entire state and every Secret, if unauthenticated |
| 6443 (or 8443/443) | kube-apiserver | the control plane — may allow anonymous read |
| 8080 | legacy apiserver insecure port | historically unauthenticated; removed in modern versions |
| 10250 | kubelet API (authenticated) | run/exec/logs on the node's pods if authz is misconfigured |
| 10255 | kubelet **read-only** port | unauthenticated pod/spec/token leakage (often still enabled) |
| 30000–32767 | NodePort services | app surface published on every node, including dashboards |

## 2. Container runtime API (Docker / containerd)

An exposed, unauthenticated Docker daemon API (TCP 2375) is complete control of the host's containers. For
an **assessment you only need to prove it answers unauthenticated** — enumerate, do not create or exec:

```bash
# Read-only probes. Getting a JSON response to /version or /containers/json unauthenticated IS the finding.
curl -s "http://$NODE:2375/version" | tee "$OUT/docker_version.json"
curl -s "http://$NODE:2375/containers/json" | tee "$OUT/docker_containers.json"   # running containers
curl -s "http://$NODE:2375/images/json"     >  "$OUT/docker_images.json"
```

Stop at enumeration. *Launching* a container (especially `--privileged` or with the host filesystem mounted)
to reach the host is the weaponized step — that is container **escape**, covered as theory in §7, not run
here. Record the exposure, the daemon version and the container/image inventory as the finding.

## 3. kubelet surface (node-local)

Every node runs a kubelet. Two ports matter:

```bash
# 10255 — READ-ONLY, unauthenticated when enabled. Pure disclosure; these are GET-only probes.
curl -s "http://$NODE:10255/pods"    | tee "$OUT/kubelet_pods.json"   # every pod spec on the node...
curl -s "http://$NODE:10255/metrics" >  "$OUT/kubelet_metrics.txt"
curl -s "http://$NODE:10255/spec/"   >  "$OUT/kubelet_spec.json"
```

The `/pods` response is high value for a *map*: it lists each pod's containers, mounted volumes and the
**names of mounted secrets and service-account tokens** — enough to understand the node's workloads without
authenticating. The authenticated kubelet API on **10250** can, when its authorization mode is
misconfigured (`--authorization-mode=AlwaysAllow`, or an anonymous role bound), expose `exec`/`run` on the
node's pods — *probe only whether it answers and whether it demands auth*; using `exec` to run commands in
someone's pod is post-exploitation, not enumeration:

```bash
# Does 10250 require authentication? A 401/403 is the healthy answer; a 200 to /pods is a finding.
curl -sk -o /dev/null -w "%{http_code}\n" "https://$NODE:10250/pods"
```

## 4. Kubernetes API server and anonymous access

The question for the control plane is simple: **does it answer anonymous callers?** A modern cluster
should return `401`/`403` for an unauthenticated request:

```bash
# Anonymous reachability + version. 403 = anonymous bound but denied; 200 to a listing = over-permissive.
curl -sk "$CLUSTER_API/version"                                   | tee "$OUT/apiserver_version.json"
curl -sk -o /dev/null -w "anon /api: %{http_code}\n" "$CLUSTER_API/api"
curl -sk -o /dev/null -w "anon namespaces: %{http_code}\n" \
  "$CLUSTER_API/api/v1/namespaces"
```

If a kubeconfig is in scope (handed to you, or recovered from an authorized source), point `kubectl` at it
and confirm you are talking to the right cluster before anything else:

```bash
export KUBECONFIG="$OUT/scoped.kubeconfig"   # an IN-SCOPE credential only
kubectl config current-context
kubectl version --output=json | tee "$OUT/kubectl_version.json"
kubectl cluster-info
```

## 5. Identity and RBAC — what *you* can do

This is the centre of a Kubernetes assessment. Rather than guessing, **ask the API what your identity is
authorized to do** — `auth can-i` is read-only and the cleanest way to measure the blast radius of the
credential you hold:

```bash
# The single most useful command: the full list of what the current identity may do.
kubectl auth can-i --list                     | tee "$OUT/can_i.txt"
kubectl auth can-i --list -n kube-system      | tee "$OUT/can_i_kube-system.txt"

# Spot-check the high-impact verbs explicitly
kubectl auth can-i create pods                 # workload creation → often a privesc primitive
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i '*' '*' --all-namespaces    # effectively cluster-admin?
```

Then enumerate the RBAC model itself — roles, bindings and which subjects hold powerful verbs — so the
report names *which* principals are over-privileged, not just that yours is:

```bash
kubectl get clusterroles,clusterrolebindings -o wide            > "$OUT/rbac_cluster.txt"
kubectl get roles,rolebindings --all-namespaces -o wide         > "$OUT/rbac_namespaced.txt"
kubectl get serviceaccounts --all-namespaces                    > "$OUT/serviceaccounts.txt"
# Who is bound to cluster-admin?
kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]?' \
  | tee "$OUT/cluster_admins.txt"
```

Record each finding as *subject → verb/resource → namespace*. Over-permissive defaults (a namespace's
`default` service account bound to broad roles, wildcard verbs, `system:anonymous` or
`system:authenticated` bound to anything) are the headline results.

## 6. Tokens, dashboards, etcd and cloud metadata

**Mounted service-account token (from inside a pod).** A pod normally mounts its token at a well-known
path. For the map you want its *claims* (namespace, service-account name, audience) — decode them
read-only rather than using the token:

```bash
TOKEN_PATH=/var/run/secrets/kubernetes.io/serviceaccount
ls -l "$TOKEN_PATH" 2>/dev/null          # token, ca.crt, namespace present = a mounted identity
```

```python
#!/usr/bin/env python3
# Decode (NOT verify) the JWT claims of a mounted SA token to see which identity the pod carries.
# Read-only: this only base64-decodes the payload; it does not call the API or use the token.
import base64, json, sys
tok = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
payload = tok.split(".")[1]
payload += "=" * (-len(payload) % 4)                       # pad base64url
claims = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps({k: claims.get(k) for k in
                  ("iss", "sub", "aud", "kubernetes.io")}, indent=2))
```

The finding is *that the pod carries an identity and what it is scoped to*; whether that token is powerful
is answered by running §5's `auth can-i` as that identity. Note whether `automountServiceAccountToken` is
left on for pods that do not need the API at all — that is a reportable default.

**Exposed dashboards and etcd.** A Kubernetes Dashboard reachable via a NodePort and granted a strong
service account, or an **unauthenticated etcd** on 2379, are each a full-cluster disclosure:

```bash
curl -sk -o /dev/null -w "dashboard: %{http_code}\n" "https://$NODE:<nodeport>/"   # from §1 NodePort range
# etcd: does it answer unauthenticated? (presence/health only — do NOT dump keys)
curl -sk -o /dev/null -w "etcd health: %{http_code}\n" "https://$NODE:2379/health"
```

etcd holds every Secret in the cluster in (often) plaintext, so an unauthenticated etcd is the single
highest-severity finding — record the exposure; **do not** read its key space.

**Cloud-metadata reachability from a pod.** On a managed cluster, a pod that can reach the node's instance
metadata service (IMDS) may be able to borrow the node's cloud identity — the container-world equivalent of
the SSRF-to-IMDS pivot in [Cloud Attack Surface Enumeration](cloud-attack-surface-enumeration.md). For the
assessment, prove *reachability*, not credential theft:

```bash
# Is 169.254.169.254 reachable from this pod? A response header is enough; do NOT pull credentials.
curl -s -o /dev/null -w "imds: %{http_code}\n" --max-time 3 http://169.254.169.254/   # AWS/Azure/GCP IMDS
```

Reachable IMDS from a workload pod is a finding on its own (it means network policy does not block the
metadata endpoint). Retrieving the node's cloud role credentials from IMDS is the weaponized pivot —
document the reachability and hand the cloud-identity angle to the cloud enumeration workflow.

## 7. Container escape and privilege escalation — *know it, detect it, harden it (not run here)*

Turning any of the above into **host or cluster compromise** — escaping a privileged container to the node,
abusing a powerful mounted token to create a `cluster-admin` binding, or scheduling a pod that mounts the
host filesystem — is where the engagement would turn weaponized. This project is
enumeration/assessment-only, so **no escape or takeover tooling or payload is published here.** You need the
model only to (a) recognise the *preconditions* while enumerating, and (b) detect and harden against it on
your own estate:

- **Know it:** [Cloud-Native Security (Containers, Kubernetes, Microservices)](../fundamentals/concepts/cloud-native-security.md)
  explains why a privileged container is "close to root on the host", why control of the API server is
  control of every workload, and the categories of control (CWPP, admission control, network policy) that
  exist to stop escape and lateral movement.
- **The preconditions you *can* report from §1–§6** are exactly what an escape needs: a privileged /
  host-mounting pod spec (visible in §3's `/pods`), a service account with `create pods` or
  `create clusterrolebindings` (§5), a reachable unauthenticated runtime/etcd (§1–§2, §6) or reachable IMDS
  (§6). Naming these preconditions *is* the deliverable — you do not need to exploit them to prove the risk.

The takeaway: an anonymous API server, an over-permissive token, an exposed runtime or a reachable IMDS is a
reportable finding on its own. You do **not** execute the escape to demonstrate that the cluster's isolation
is too weak.

## Detect it

Enumeration against a cluster is **visible in the control plane's audit log** — the API server records every
request with the calling identity, verb, resource and decision. The reachability probes (§1–§4, §6) also
surface as connection attempts and anonymous `401/403`s. Pair each technique with where a defender catches
it on their own estate:

| Offensive technique here | Detect it with |
| :--- | :--- |
| Anonymous / over-permissive API calls, RBAC probing (`auth can-i`, bulk `get`) (§4–§5) | Kubernetes audit log — on AKS, the `kube-audit` / `kube-audit-admin` categories queried in KQL: [Azure Kubernetes Service (AKS)](../platforms/azure/kubernetes.md) (§5 Audit logs) |
| Anomalous workload/identity activity across cloud-native infra (§2–§6) | [Cloud infrastructure ephemeral-asset hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) · respond: [Azure resource hijacking](../tasks/incident-response/azure-resource-hijacking.md) |
| Stolen kubeconfig / service-account token surfacing from a pipeline (§6) | [Sigma — CI/CD Secret Leak in Build Logs](../detection/sigma/cicd-secret-leak.md) |

A dedicated, vendor-neutral Kubernetes-audit SPL/KQL/Sigma page is not published on the
[Detection](../detection/index.md) tab yet — until it is, the AKS audit-log guidance above is the closest
query-level reference, and the control-plane audit log (enabled first — a cluster with auditing off cannot
detect any of this) is the primary source. Note that §2/§6 unauthenticated runtime and read-only kubelet
probes may leave **no application log at all**, which is itself the argument for network-level controls.

## Harden it

Every finding on this page maps to a control:

- **Turn off anonymous and read-only surfaces.** Disable the kubelet read-only port (`--read-only-port=0`),
  set the kubelet authorization mode to `Webhook`, and ensure the API server does not bind
  `system:anonymous`/`system:authenticated` to anything useful. Never expose the Docker API on 2375, and put
  etcd behind client-cert auth with encryption-at-rest for Secrets.
- **Least-privilege RBAC.** Scope service accounts to the minimum verbs, avoid wildcard roles and broad
  `cluster-admin` bindings, and set `automountServiceAccountToken: false` for workloads that never call the
  API. §5's `auth can-i --list` output is the before/after evidence.
- **Managed-cluster baseline.** On AKS, restrict the API server with authorized IP ranges, disable local
  accounts in favour of Entra RBAC, and enable audit logging —
  [Azure Security Baseline (AKS controls)](../tasks/hardening/cloud-azure-security-baseline.md) and the
  [Azure Kubernetes Service (AKS)](../platforms/azure/kubernetes.md) settings page.
- **Block pod→metadata and lock down escape preconditions.** A network policy that denies pods egress to
  `169.254.169.254` closes the IMDS pivot (§6); admission control / Pod Security that forbids privileged and
  host-mounting pods closes the escape preconditions (§7). The dedicated, step-by-step controls — one
  per finding on this page — are in
  [Container & Kubernetes Hardening](../tasks/hardening/container-kubernetes-hardening.md), with the
  AKS baseline above and the [Cloud-Native Security](../fundamentals/concepts/cloud-native-security.md)
  concept's *Detect it* / *Harden* links for the surrounding context.

## Notes

- **Map, don't take over.** Prove that a surface is reachable, anonymous or over-permissive and stop —
  escape, token abuse and cluster-admin escalation are theory + detect/harden only (§7).
- **`auth can-i --list` is the headline.** The most valuable single artefact is an evidenced list of what
  each identity (yours, the `default` SA, `system:anonymous`) is authorized to do.
- **Unauthenticated etcd and the Docker API on 2375 are top-severity** — a reachable, unauthenticated one is
  the whole cluster. Record the exposure; do not dump its contents.
- **Secrets stay in the evidence store.** Tokens, kubeconfigs and registry creds you discover are live —
  never put them in the report body or a chat.
- **Enable the audit log before you blame the SIEM.** Much of §2/§6 leaves little application trace; a
  cluster with auditing off is invisible to the detections above.
- Install notes: `kubectl`, `curl`, `jq`, `nmap` and Python 3 ship on or `apt install` onto Parrot/Kali;
  point `kubectl` only at an in-scope `KUBECONFIG`.

## Related

- [Offensive — Overview](index.md) — this is part of Stage 1 (Reconnaissance)
- [Enumerate Cloud Attack Surface across AWS, Azure and GCP](cloud-attack-surface-enumeration.md) — the IaaS/identity layer beneath the cluster (IMDS/SSRF pivot continues there) · [Map an Organization's Attack Surface with OSINT and Active Reconnaissance](osint-active-recon.md)
- Reference: [Cloud-Native Security (Containers, Kubernetes, Microservices)](../fundamentals/concepts/cloud-native-security.md) · [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md) · [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md) · [Identity and Access Management](../fundamentals/concepts/identity-access-management.md)
- Defensive counterparts: [Container & Kubernetes Hardening](../tasks/hardening/container-kubernetes-hardening.md) — the step-by-step control page for this surface · [Azure Kubernetes Service (AKS)](../platforms/azure/kubernetes.md) · [Azure Security Baseline](../tasks/hardening/cloud-azure-security-baseline.md)

## External Resources & White Papers

- [Kubernetes — Controlling Access to the API](https://kubernetes.io/docs/concepts/security/controlling-access/) · [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) — the authorization model §4–§5 measure
- [NSA/CISA — Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) — the authoritative control mapping behind *Harden it*
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — node, API server, etcd and kubelet settings this page enumerates
- [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/) — the risk framing (misconfigured RBAC, exposed surfaces, over-permissive identities)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) — technique IDs for the Detect-it mapping
