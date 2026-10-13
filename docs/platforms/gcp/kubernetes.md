---
title: Google Kubernetes Engine (GKE)
platforms: [GCP]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Containers
tags: [gcp, gke, kubernetes, workload identity federation for gke, private cluster, binary authorization, gke autopilot, kubernetes audit logs, rbac]
aliases: [gcloud container clusters get-credentials, gke workload identity, gke audit logs query, gke private cluster, gke node service account, gke security posture]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Google Kubernetes Engine (GKE)

GKE runs Kubernetes with a Google-managed control plane. Access to the API server is **IAM** (who can get credentials) plus **Kubernetes RBAC** (what they can do inside). Pods should reach Google APIs through **Workload Identity Federation for GKE**, never through the node's service account or key files.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Commands that change state are marked **change**.

## 1. Inventory and connect

```bash
gcloud container clusters list --format="table(name, location, currentMasterVersion, autopilot.enabled, privateClusterConfig.enablePrivateNodes, workloadIdentityConfig.workloadPool)"
gcloud container clusters describe <cluster> --location=<region-or-zone> --format=json > cluster.json
gcloud container clusters get-credentials <cluster> --location=<region-or-zone>
kubectl auth whoami
kubectl get nodes -o wide
```

## 2. Security settings to check

| Setting | Field in `cluster.json` | Want |
| :--- | :--- | :--- |
| Workload Identity | `workloadIdentityConfig.workloadPool` | `<project>.svc.id.goog` |
| Private nodes | `privateClusterConfig.enablePrivateNodes` | `true` |
| Control plane access | `masterAuthorizedNetworksConfig` | Enabled, narrow CIDRs (or DNS endpoint with IAM) |
| Legacy ABAC | `legacyAbac.enabled` | absent / `false` |
| Basic auth / client certs | `masterAuth` | No password, no client certificate |
| Node service account | `nodeConfig.serviceAccount` | Dedicated minimal SA, not default compute |
| Shielded nodes, secure boot | `shieldedNodes`, `nodeConfig.shieldedInstanceConfig` | Enabled |
| Binary Authorization | `binaryAuthorization.evaluationMode` | `PROJECT_SINGLETON_POLICY_ENFORCE` |

Autopilot clusters enforce most of these by default.

## 3. Workload Identity Federation for GKE

```bash
# change: enable on an existing cluster and node pool
gcloud container clusters update <cluster> --location=<loc> --workload-pool=<PROJECT_ID>.svc.id.goog
gcloud container node-pools update <pool> --cluster=<cluster> --location=<loc> --workload-metadata=GKE_METADATA

# change: grant a Kubernetes service account direct IAM access (no Google SA needed)
gcloud projects add-iam-policy-binding <PROJECT_ID> --role=roles/storage.objectViewer \
  --member="principal://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<PROJECT_ID>.svc.id.goog/subject/ns/<namespace>/sa/<ksa>"
```

With `GKE_METADATA`, pods cannot read the node's own credentials from the metadata server.

## 4. RBAC review

```bash
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name + " -> " + ([.subjects[]? | .kind + ":" + .name] | join(", "))'
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl get rolebindings,clusterrolebindings -A -o wide | grep -E "system:(anonymous|unauthenticated|authenticated)"
```

IAM roles `roles/container.admin` and `roles/container.clusterAdmin` grant full access regardless of RBAC; grant `roles/container.clusterViewer` plus RBAC for most people.

## 5. GKE audit logs

Kubernetes API audit logs flow into Cloud Logging as `k8s_cluster` resources (Admin Activity always on; Data Access for reads).

```bash
gcloud logging read 'resource.type="k8s_cluster" AND resource.labels.cluster_name="<cluster>"
  AND protoPayload.methodName=("io.k8s.core.v1.pods.exec.create" OR "io.k8s.core.v1.pods.attach.create")' \
  --freshness=7d --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.resourceName)"

gcloud logging read 'resource.type="k8s_cluster" AND protoPayload.methodName:"clusterrolebindings.create"' --freshness=30d
gcloud logging read 'resource.type="k8s_cluster" AND protoPayload.authenticationInfo.principalEmail="system:anonymous"' --freshness=7d
```

## 6. Posture and threats

- **GKE security posture** dashboard: workload configuration and OS/language vulnerability scanning.
- **Security Command Center**: GKE findings from Container Threat Detection (reverse shells, added binaries) ([Security posture](security-posture.md)).
- **Binary Authorization**: only images signed by your pipeline run.

## 7. Contain a compromised pod or node

```bash
kubectl label pod <pod> -n <ns> quarantine=true
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: quarantine, namespace: <ns>}
spec: {podSelector: {matchLabels: {quarantine: "true"}}, policyTypes: [Ingress, Egress]}
EOF
kubectl cordon <node>                          # change: no new pods; then snapshot the node disk
```

Network policies need Dataplane V2 or network policy enforcement enabled. Then follow [Incident response](incident-response.md#3-preserve-evidence) for the node VM.

## Related

- [Identity & access](identity-access.md)
- [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md)
- [Detection: cryptomining](../../detection/sigma/cryptomining.md)

## Sources

- [Harden your cluster's security](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [Workload Identity Federation for GKE](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- [GKE audit logging](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging)
- [Binary Authorization](https://cloud.google.com/binary-authorization/docs/overview)
