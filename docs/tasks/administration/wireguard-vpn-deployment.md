---
title: Administration — WireGuard Secure VPN Gateway & Client Deployment
type: workflow
platforms:
  - Linux
  - Windows
languages:
  - Bash
  - PowerShell
tasks:
  - Administration
  - Hardening
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - vpn
  - wireguard
  - networking
  - tunnel
  - gateway
  - hardening
---

# Administration — WireGuard Secure VPN Gateway & Client Deployment

Production deployment runbook for building a hardened, high-performance Linux WireGuard VPN gateway, configuring automated peer provisioning, enforcing split vs full tunneling, and optimizing MTU/MSS to prevent silent TCP packet drops.

---

## 1. Gateway Server Installation & Key Generation

WireGuard operates entirely inside the Linux kernel, utilizing modern asymmetric cryptography (Curve25519, ChaCha20-Poly1305, BLAKE2s) over UDP.

### Install Packages & Enable Kernel IP Forwarding
```bash
# 1. Install WireGuard and network tools
sudo apt-get update && sudo apt-get install -y wireguard iptables qrencode

# 2. Persist IPv4 packet forwarding in sysctl
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-wireguard.conf
sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
```

### Generate Server Cryptographic Keypair
```bash
# Generate server private and public keys with strict permissions
umask 077
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
```

---

## 2. Server Configuration (`/etc/wireguard/wg0.conf`)

Configure the VPN gateway network interface (`10.100.0.1/24`), listening port (`51820`), and iptables NAT packet forwarding rules:

```ini
[Interface]
Address = 10.100.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>
SaveConfig = false

# Enable NAT packet masquerading on outbound physical interface (e.g. eth0)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o <OUTBOUND_INTERFACE> -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o <OUTBOUND_INTERFACE> -j MASQUERADE

# TCP MSS Clamping (Prevents packet fragmentation hangs on PMTU mismatches)
PostUp = iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

```bash
# Enable and start the WireGuard systemd service
sudo systemctl enable --now wg-quick@wg0

# Check live interface state
sudo wg show wg0
```

---

## 3. Client Provisioning: Full Tunnel vs Split Tunnel

Each client workstation requires its own asymmetric keypair. The client is assigned a static IP inside the VPN subnet.

### Generate Client Keypair
```bash
umask 077
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

### Register Client Peer on Server
```bash
# Add peer dynamically to live running interface
sudo wg set wg0 peer "$(cat client_public.key)" allowed-ips 10.100.0.2/32
```

### Option A: Full Tunnel Client Profile (`client-full.conf`)
Routes 100% of workstation Internet and corporate traffic through the VPN gateway:

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.100.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <GATEWAY_PUBLIC_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### Option B: Split Tunnel Client Profile (`client-split.conf`)
Routes only internal corporate subnets (`10.100.0.0/24`, `192.168.10.0/24`) through the VPN, sending standard Internet traffic directly:

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.100.0.2/24
DNS = 10.100.0.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <GATEWAY_PUBLIC_IP>:51820
AllowedIPs = 10.100.0.0/24, 192.168.10.0/24
PersistentKeepalive = 25
```

### Export Mobile QR Code
```bash
# Render client configuration as terminal QR code for iOS / Android onboarding
qrencode -t ansiutf8 < client-split.conf
```

---

## 4. MTU Clamping & Troubleshooting Silent Packet Drops

A common VPN operational pitfall is **MTU mismatch**: standard Ethernet frames are 1500 bytes, but WireGuard adds an 80-byte encapsulation header (or more when encapsulated over PPPoE or cloud underlays). If packets exceed MTU and intermediate routers drop ICMP "Fragmentation Needed" packets, TCP connections stall indefinitely after the initial TLS handshake.

### MTU Optimization
- If connections stall when downloading files or loading HTTPS pages, lower the client MTU in the `[Interface]` section:
  ```ini
  MTU = 1360
  ```

### Verify Active Tunnel Handshake & Bytes Transferred
```bash
# Check latest handshake timestamp (handshake must occur every 120-180 seconds)
sudo wg show wg0 latest-handshakes

# Check transfer throughput per peer
sudo wg show wg0 transfer
```

```powershell
# Windows: Verify WireGuard tunnel interface and ping gateway
Get-NetAdapter | Where-Object InterfaceDescription -like "*WireGuard*"
Test-NetConnection -ComputerName "10.100.0.1" -InformationLevel Detailed
```

---

## Related Guides

- [Fundamentals — VPN Protocols (IPsec vs SSL/TLS)](../../fundamentals/networking/vpn.md)
- [Troubleshooting — Windows Network & Domain Connectivity](../troubleshooting/windows-connectivity.md)
- [Linux Firewall & nftables Administration](../../platforms/linux/firewalls-nftables.md)
- [Remote File Transfer — SCP, SFTP, rsync & WinRM](remote-file-transfer.md)
