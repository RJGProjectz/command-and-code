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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - vpn
  - ipsec
  - ikev2
  - wireguard
aliases: [Virtual Private Networks]
---

# Fundamentals — VPN Protocols (IPsec vs SSL/TLS)

Virtual Private Networks (VPNs) encapsulate and encrypt private network traffic across untrusted public networks.

Two common uses: **remote access** (a laptop joins the corporate network) and **site-to-site** (two networks joined permanently). VPN gateways face the internet and hold the keys to the internal network, so they are one of the most targeted systems: exploits in Ivanti, Fortinet, Palo Alto, Cisco and Citrix gateways have been used for initial access again and again.

## 1. Protocol Comparison

| Protocol | Ports | Layer | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **IKEv2 / IPsec** | UDP 500, UDP 4500 (NAT-T), Protocol 50 (ESP) | Layer 3 | High throughput, seamless mobile reconnection (MOBIKE), native in Windows, macOS, iOS, Android | Blocked by restrictive firewalls; complex configuration |
| **OpenVPN (SSL)** | UDP 1194 (default) or TCP 443 | Layer 3 (tun) or 2 (tap) | Works through most firewalls when on TCP 443 | Higher CPU overhead; TCP-over-TCP is slow on lossy links |
| **WireGuard** | UDP (Configurable, e.g. 51820) | Layer 3 | Modern cryptographic primitives (ChaCha20, Curve25519), extremely lean, small code base | UDP only; static keys, no built-in user authentication |
| **Vendor SSL VPN** (Fortinet, Palo Alto GlobalProtect, Cisco AnyConnect, Ivanti) | TCP 443 (+ UDP/DTLS) | Layer 3 | SSO/MFA, device posture checks | Large web-facing attack surface; frequent critical CVEs |

## 2. IPsec Phase 1 & Phase 2 Mechanics

- **Phase 1 (IKE SA)**: Authenticates endpoints (Pre-Shared Key or Certificates) and negotiates an encrypted tunnel to protect subsequent management messages.
- **Phase 2 (IPsec SA / Child SA)**: Negotiates the specific transform sets (AES-GCM) and encryption keys used for the actual payload data passing across the tunnel.

Both ends must agree on the same proposals (encryption, integrity, Diffie-Hellman group, lifetimes). A mismatch is the most common reason a tunnel does not come up: check the logs on both sides for "no proposal chosen".

## 3. Hardening checklist

- **MFA for every remote-access user**, ideally through SSO with conditional access.
- **Patch the gateway first** when a VPN CVE is published; these are exploited within days. Subscribe to the vendor's advisories and CISA's Known Exploited Vulnerabilities catalogue.
- **Certificates over pre-shared keys** for IPsec; a shared PSK across many peers is one leak away from compromise.
- **Strong suites only**: IKEv2, AES-GCM, DH group 19/20/21 or higher; disable IKEv1 aggressive mode, 3DES, SHA-1 and DH groups 1, 2 and 5.
- **Split tunnelling** is a trade-off: it reduces load, but internet traffic from the laptop then bypasses your web filtering.
- **Restrict access after connect**: VPN users should reach the applications they need, not the whole network (see [microsegmentation](microsegmentation.md)).

## 4. Investigate VPN access

- Successful logins from unusual countries, impossible travel, or at odd hours.
- One account connected from two places at once.
- Logins that succeed right after a burst of failures (password spraying).
- New local accounts or configuration changes on the gateway itself; check its integrity tool if the vendor provides one.

→ [Account compromise](../../tasks/incident-response/account-compromise.md) · [Failed authentication](../../tasks/investigation/failed-authentication.md)

## Related

- [WireGuard VPN deployment](../../tasks/administration/wireguard-vpn-deployment.md)
- [Microsegmentation](microsegmentation.md)

## Sources

- [RFC 7296 — IKEv2](https://www.rfc-editor.org/rfc/rfc7296)
- [NSA/CISA — Selecting and Hardening Remote Access VPN Solutions](https://media.defense.gov/2021/Sep/28/2002863184/-1/-1/0/CSI_SELECTING-HARDENING-REMOTE-ACCESS-VPNS-20210928.PDF)
- [WireGuard — technical whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [CISA — Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
