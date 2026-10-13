---
title: Amazon Elastic Kubernetes Service (EKS)
platforms: [AWS]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Containers
tags: [aws, eks, kubernetes, kubectl, access entries, irsa, pod identity, eks audit logs, aws-auth]
aliases: [eks update-kubeconfig, eks access entries, eks aws-auth configmap, eks irsa, eks pod identity, eks audit log query, eks public endpoint]
difficulty: advanced
verified: true
last_verified: 2026-10-12
---

# Amazon Elastic Kubernetes Service (EKS)

EKS runs the Kubernetes control plane. **IAM** decides who can authenticate to the cluster. **Access entries** (or the legacy `aws-auth` ConfigMap) map IAM principals to Kubernetes identities, and **Kubernetes RBAC** decides what those identities can do. Pods get AWS permissions through **IRSA** or **EKS Pod Identity**. See [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md) for the model.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. Inventory and security settings

```bash
aws eks list-clusters --output table
aws eks describe-cluster --name <cluster> --query "cluster.{version:version, endpointPublic:resourcesVpcConfig.endpointPublicAccess, publicCidrs:resourcesVpcConfig.publicAccessCidrs, private:resourcesVpcConfig.endpointPrivateAccess, authMode:accessConfig.authenticationMode, logging:logging.clusterLogging, secretsKms:encryptionConfig}"
```

| Setting | Secure value | Why |
| :--- | :--- | :--- |
| Public endpoint | Off, or `publicAccessCidrs` restricted | Default is open to `0.0.0.0/0` |
| `authenticationMode` | `API` (access entries) | `aws-auth` ConfigMap edits are easy to miss and break |
| Control-plane logging | `api`, `audit`, `authenticator` enabled | Off by default |
| Secrets encryption | KMS key configured | Envelope-encrypts Kubernetes Secrets |
| IMDS hop limit on nodes | 1 | Stops pods stealing the node role ([EC2](compute.md#5-enforce-imdsv2)) |

## 2. Get credentials

```bash
aws eks update-kubeconfig --name <cluster> --region <region> --alias <cluster>
kubectl auth whoami
kubectl auth can-i --list
```

## 3. Who can administer the cluster?

```bash
aws eks list-access-entries --cluster-name <cluster> --output table
aws eks list-associated-access-policies --cluster-name <cluster> --principal-arn <arn> \
  --query "associatedAccessPolicies[].{policy:policyArn, scope:accessScope.type}" --output table

# Legacy mapping, if the cluster still uses it
kubectl -n kube-system get configmap aws-auth -o yaml

kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name + " -> " + ([.subjects[]? | .kind + ":" + .name] | join(", "))'
```

The IAM principal that **created** the cluster may have hidden cluster-admin (`bootstrapClusterCreatorAdminPermissions`). Check for an access entry with `AmazonEKSClusterAdminPolicy`.

## 4. Pod-level AWS permissions

```bash
# IRSA: service accounts annotated with a role
kubectl get sa -A -o json | jq -r '.items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"]) | .metadata.namespace + "/" + .metadata.name + " -> " + .metadata.annotations["eks.amazonaws.com/role-arn"]'

# Pod Identity associations
aws eks list-pod-identity-associations --cluster-name <cluster> --output table
```

Then review each role's IAM policies ([IAM](identity-access.md)). A pod that can create pods in that namespace can use the role.

## 5. Workloads at a glance

```bash
kubectl get pods -A -o json | jq -r '.items[] | select(any(.spec.containers[]; .securityContext.privileged==true)) | .metadata.namespace + "/" + .metadata.name'
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true) | .metadata.namespace + "/" + .metadata.name'
kubectl get svc -A --field-selector spec.type=LoadBalancer
```

## 6. Audit logs (CloudWatch Logs)

```bash
# change: enable control-plane logs
aws eks update-cluster-config --name <cluster> --logging '{"clusterLogging":[{"types":["api","audit","authenticator"],"enabled":true}]}'
```

Logs land in `/aws/eks/<cluster>/cluster`.

```sql
-- Logs Insights: exec into pods, secret reads and RBAC changes
fields @timestamp, user.username, verb, objectRef.resource, objectRef.namespace, objectRef.name, sourceIPs.0
| filter @logStream like /kube-apiserver-audit/
| filter (objectRef.resource = "pods" and objectRef.subresource = "exec")
      or objectRef.resource in ["secrets", "clusterrolebindings", "rolebindings"]
| filter verb not in ["watch"]
| sort @timestamp desc
| limit 200
```

GuardDuty **EKS Protection** and **Runtime Monitoring** analyze these logs and node activity for you ([Security posture](security-posture.md)).

## 7. Incident actions (change)

```bash
kubectl cordon <node>                                      # stop scheduling onto a suspect node
kubectl label pod <pod> -n <ns> quarantine=true            # then apply a deny-all NetworkPolicy selecting it
aws eks delete-access-entry --cluster-name <cluster> --principal-arn <arn>
aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true
```

To keep evidence from a node, snapshot its EBS volumes and isolate the instance as described in [Incident response](incident-response.md#3-preserve-evidence) before you terminate it. Auto Scaling would otherwise replace it and destroy the disk.

## Related

- [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md)
- [IAM](identity-access.md)
- [Azure AKS](../azure/kubernetes.md) for the same tasks on Azure

## Sources

- [EKS access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html)
- [IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [EKS control plane logging](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)
