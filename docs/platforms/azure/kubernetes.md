---
title: Azure Kubernetes Service (AKS)
platforms: [Azure]
languages: [Bash, KQL]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Containers
tags: [azure, aks, kubernetes, kubectl, entra id, workload identity, kube-audit, container insights]
aliases: [aks get credentials, aks local accounts disabled, aks audit logs kql, aks workload identity, aks api server authorized ip, aks cluster admin]
difficulty: advanced
verified: true
last_verified: 2026-10-12
---

# Azure Kubernetes Service (AKS)

AKS runs the Kubernetes control plane for you. Two permission layers apply: **Azure RBAC** on the cluster resource, which decides who can fetch credentials, and **Kubernetes RBAC** (or Azure RBAC for Kubernetes), which decides what they can do inside it. See [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md) for the general model.

!!! warning "Before you run anything"
    Every command was checked against the Azure CLI reference and Microsoft Learn (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. Inventory and security settings

```bash
az aks list --query "[].{name:name, rg:resourceGroup, version:kubernetesVersion, private:apiServerAccessProfile.enablePrivateCluster, localAccounts:disableLocalAccounts, aad:aadProfile.managed, azureRbac:aadProfile.enableAzureRbac}" -o table
az aks show -g <rg> -n <cluster> --query "{authorizedIps:apiServerAccessProfile.authorizedIpRanges, oidcIssuer:oidcIssuerProfile.enabled, workloadIdentity:securityProfile.workloadIdentity.enabled, defender:securityProfile.defender}"
```

| Setting | Secure value | Why |
| :--- | :--- | :--- |
| `disableLocalAccounts` | `true` | Otherwise `--admin` credentials give cluster-admin with a static cert that ignores Entra ID |
| Private cluster or `authorizedIpRanges` | set | API server is public by default |
| Entra ID integration + Azure RBAC | enabled | Access follows Entra ID groups, Conditional Access and PIM |
| Workload identity | enabled | Pods get federated tokens instead of stored secrets |

## 2. Get credentials

```bash
az aks get-credentials -g <rg> -n <cluster>              # user credentials (Entra ID)
kubelogin convert-kubeconfig -l azurecli                 # use the az login session
kubectl auth whoami
kubectl auth can-i --list
```

`az aks get-credentials --admin` returns cluster-admin. Calling it is logged as `MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/LISTCLUSTERADMINCREDENTIAL/ACTION`; alert on it.

## 3. Who is cluster-admin?

```bash
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name + " -> " + ([.subjects[]? | .kind + ":" + .name] | join(", "))'

az role assignment list --scope $(az aks show -g <rg> -n <cluster> --query id -o tsv) --include-inherited -o table
```

## 4. Workloads at a glance

```bash
kubectl get pods -A -o wide
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + "/" + .metadata.name'
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true) | .metadata.namespace + "/" + .metadata.name'
kubectl get svc -A --field-selector spec.type=LoadBalancer
```

## 5. Audit logs

Enable the `kube-audit-admin` (writes only, cheaper) or `kube-audit` category on the cluster's diagnostic setting.

```bash
# change
az monitor diagnostic-settings create -n aks-audit --resource <aks-id> --workspace <law-id> \
  --logs '[{"category":"kube-audit-admin","enabled":true},{"category":"guard","enabled":true}]'
```

```kusto
// Exec into pods, secret reads and RBAC changes
AKSAuditAdmin
| where TimeGenerated > ago(1d)
| where (ObjectRef.resource == "pods" and ObjectRef.subresource == "exec")
     or ObjectRef.resource in ("clusterrolebindings", "rolebindings", "secrets")
| project TimeGenerated, User = tostring(User.username), Verb, Resource = tostring(ObjectRef.resource),
          Namespace = tostring(ObjectRef.namespace), Name = tostring(ObjectRef.name), SourceIps
```

(Clusters using the older `AzureDiagnostics` mode log to `AzureDiagnostics | where Category == "kube-audit"` with the event JSON in `log_s`.)

## 6. Container Insights

```kusto
ContainerLogV2
| where TimeGenerated > ago(1h) and PodNamespace == "prod"
| where LogMessage has_any ("error", "denied", "unauthorized")
| project TimeGenerated, PodName, ContainerName, LogMessage
```

## 7. Incident actions (change)

```bash
kubectl cordon <node>                                     # stop new pods landing on a suspect node
kubectl label pod <pod> -n <ns> quarantine=true           # then apply a deny-all NetworkPolicy selecting it
az aks command invoke -g <rg> -n <cluster> --command "kubectl get pods -A"   # works on private clusters
az aks rotate-certs -g <rg> -n <cluster>                  # rotates cluster certs; brief API outage
```

To capture a compromised node, snapshot its OS disk from the node resource group (`MC_<rg>_<cluster>_<region>`), as described in [Incident response](incident-response.md#3-preserve-evidence).

## Related

- [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md)
- [Identity & access](identity-access.md)
- [Security posture](security-posture.md) (Defender for Containers)

## Sources

- [AKS security concepts](https://learn.microsoft.com/azure/aks/concepts-security)
- [Disable local accounts](https://learn.microsoft.com/azure/aks/manage-local-accounts-managed-azure-ad)
- [AKS resource logs](https://learn.microsoft.com/azure/aks/monitor-aks-reference)
