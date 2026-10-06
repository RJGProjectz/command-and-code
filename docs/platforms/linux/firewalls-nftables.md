---
title: Linux Firewalls — nftables, iptables & UFW Defense
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - linux
  - firewalls
  - nftables
  - iptables
---

# Linux Firewalls — nftables, iptables & UFW Defense

Configuration of host-based firewalls in Linux using `nftables` (modern default) and `iptables`.

## 1. Modern nftables Baseline Configuration

```bash
# Flush and apply a hardened default-drop configuration
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \\; policy drop \\; }
nft add chain inet filter forward { type filter hook forward priority 0 \\; policy drop \\; }
nft add chain inet filter output { type filter hook output priority 0 \\; policy accept \\; }

# Allow established connections and loopback
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept

# Allow SSH from management subnet only
nft add rule inet filter input ip saddr 10.10.0.0/24 tcp dport 22 accept
```
