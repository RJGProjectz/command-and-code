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
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - zero-trust
  - microsegmentation
  - hardening
  - defense-in-depth
---

# Fundamentals — Zero Trust Network Microsegmentation

Microsegmentation isolates workloads and applications at the host or hypervisor layer, enforcing least-privilege lateral communication boundaries.

## 1. Perimeter vs Microsegmented Architecture

```text
[Legacy Perimeter Model]
[Untrusted Internet] ──► [Edge Firewall] ──► [Flat Internal Network (Any-to-Any Lateral Movement)]

[Zero Trust Microsegmentation]
[Workload A] ──(Host Policy: Allow Port 443 Only)──► [Workload B]
      ▲                                                      │
      └─── (Port 445 / RDP Blocked by Default) ──────────────┘
```

## 2. Enforcement Mechanisms

- **Host-Based Enforcement**: Distributed firewall rules managed centrally (e.g. `nftables`, Windows Defender Firewall with Advanced Security).
- **Service Mesh**: Envoy / Istio sidecar proxies terminating mutual TLS (mTLS) between microservices with SPIFFE/SPIRE cryptographic workload identities.
- **Identity-Aware Access**: Software-Defined Perimeter (SDP) granting ephemeral network sockets based on device posture and user identity.
