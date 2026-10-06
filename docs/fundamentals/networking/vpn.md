---
title: Fundamentals — VPN Protocols (IPsec vs SSL/TLS)
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Troubleshooting
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - vpn
  - ipsec
  - ikev2
  - wireguard
---

# Fundamentals — VPN Protocols (IPsec vs SSL/TLS)

Virtual Private Networks (VPNs) encapsulate and encrypt private network traffic across untrusted public networks.

## 1. Protocol Comparison

| Protocol | Ports | Layer | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **IKEv2 / IPsec** | UDP 500, UDP 4500 (NAT-T), Protocol 50 (ESP) | Layer 3 | High throughput, seamless mobile reconnection (MOBIKE) | Blocked by restrictive firewalls |
| **OpenVPN (SSL)** | UDP 1194 (default) or TCP 443 | Layer 3/4 | Bypasses deep packet inspection when over TCP 443 | Higher CPU overhead |
| **WireGuard** | UDP (Configurable, e.g. 51820) | Layer 3 | Modern cryptographic primitives (ChaCha20, Curve25519), extremely lean | UDP only |

---

## 2. IPsec Phase 1 & Phase 2 Mechanics

- **Phase 1 (IKE SA)**: Authenticates endpoints (Pre-Shared Key or Certificates) and negotiates an encrypted tunnel to protect subsequent management messages.
- **Phase 2 (IPsec SA / Child SA)**: Negotiates the specific transform sets (AES-GCM) and encryption keys used for the actual payload data passing across the tunnel.
