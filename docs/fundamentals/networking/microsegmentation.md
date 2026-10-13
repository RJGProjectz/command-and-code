---
title: Fundamentals — Zero Trust Network Microsegmentation
type: entry
platforms:
  - Linux
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Hardening
  - Assurance
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - zero-trust
  - microsegmentation
  - hardening
  - defense-in-depth
---

# Fundamentals — Zero Trust Network Microsegmentation

Microsegmentation isolates workloads and applications at the host or hypervisor layer, enforcing least-privilege lateral communication boundaries.

**Why it matters:** most intrusions start on one workstation or server and spread sideways over SMB, RDP, WinRM, SSH and database ports. In a flat network, every machine can reach every other, so one foothold reaches everything. Segmentation turns "the attacker is inside" into "the attacker is inside one small zone".

## 1. Perimeter vs Microsegmented Architecture

```text
[Legacy Perimeter Model]
[Untrusted Internet] ──► [Edge Firewall] ──► [Flat Internal Network (Any-to-Any Lateral Movement)]

[Zero Trust Microsegmentation]
[Workload A] ──(Host Policy: Allow Port 443 Only)──► [Workload B]
      ▲                                                      │
      └─── (Port 445 / RDP Blocked by Default) ──────────────┘
```

| Approach | Boundary | Granularity |
| --- | --- | --- |
| VLANs + internal firewall | Subnet | Coarse; traffic inside a VLAN is unrestricted |
| Microsegmentation | Each workload or application | Fine; rules follow the workload, not the IP range |

## 2. Enforcement Mechanisms

- **Host-Based Enforcement**: Distributed firewall rules managed centrally (e.g. `nftables`, Windows Defender Firewall with Advanced Security pushed by Group Policy or Intune).
- **Hypervisor / cloud**: VMware NSX distributed firewall, Azure Network Security Groups and Application Security Groups, AWS Security Groups, GCP firewall rules with network tags or service accounts.
- **Kubernetes**: `NetworkPolicy` objects (enforced by the CNI plug-in, such as Calico or Cilium) between pods.
- **Service Mesh**: Envoy / Istio sidecar proxies terminating mutual TLS (mTLS) between microservices with SPIFFE/SPIRE cryptographic workload identities.
- **Identity-Aware Access**: Software-Defined Perimeter (SDP) / ZTNA granting access to one application at a time based on device posture and user identity, instead of a full-network VPN.

## 3. Rolling it out without breaking things

1. **Map flows first.** Collect who talks to whom (firewall logs, NetFlow, EDR network events, cloud flow logs) for a few weeks.
2. **Group workloads by role** (web, app, database, domain controllers, management) and write allow rules between groups.
3. **Monitor mode.** Log what the new policy *would* block before enforcing.
4. **Enforce the high-value rules first**, which cost little and block the most:
   - workstation ↔ workstation: block SMB (445), RDP (3389), WinRM (5985/5986), RPC (135);
   - only admin jump hosts may reach management ports on servers;
   - databases accept connections only from their application servers.
5. **Default deny** between zones once the flow map is stable.

## 4. Verify it

```powershell
# From a workstation: management ports on another workstation should be unreachable
Test-NetConnection -ComputerName <other-workstation> -Port 445
Test-NetConnection -ComputerName <other-workstation> -Port 3389
```

```bash
# From an app server: the database is reachable, admin ports on peers are not
timeout 3 bash -c "</dev/tcp/<db-host>/5432" && echo open || echo blocked
timeout 3 bash -c "</dev/tcp/<peer-host>/22" && echo open || echo blocked
```

## Related

- [Host firewall default-deny check](../../tasks/assurance/firewall-default-deny.md)
- [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md)
- [SMB fundamentals](../smb.md)

## Sources

- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [CISA — Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [Kubernetes — Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
