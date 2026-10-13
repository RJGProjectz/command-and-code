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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - linux
  - firewalls
  - nftables
  - iptables
aliases: [Firewalls]
---

# Linux Firewalls — nftables, iptables & UFW Defense

Configuration of host-based firewalls in Linux using `nftables` (modern default) and `iptables`.

## 0. Which tool is in charge?

Current distributions (Debian 10+, Ubuntu 20.04+, RHEL 8+) use **nftables** in the kernel. `iptables` is usually the `iptables-nft` wrapper that writes nftables rules, and **UFW** (Ubuntu) and **firewalld** (RHEL family) are front ends on top. Manage the firewall with one tool only; rules added by another tool get overwritten or hidden.

```bash
iptables -V                   # "(nf_tables)" = wrapper over nftables; "(legacy)" = old backend
systemctl is-active nftables ufw firewalld 2>/dev/null
nft list ruleset              # everything actually loaded, whatever tool created it
```

## 1. Modern nftables Baseline Configuration

Build the rules **before** switching the policy to drop, or a remote session is cut off halfway through. Keep a console (or out-of-band) session open while you work.

```bash
# Table and chains, still accepting while rules are added
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy accept; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy accept; }'
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'

# Stateful basics, loopback, and the ICMP that IPv4/IPv6 need to work
nft add rule inet filter input ct state invalid drop
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept
nft add rule inet filter input meta l4proto ipv6-icmp accept
nft add rule inet filter input ip protocol icmp accept

# Allow SSH from management subnet only
nft add rule inet filter input ip saddr 10.10.0.0/24 tcp dport 22 accept

# Now close everything else
nft 'chain inet filter input { policy drop; }'
nft 'chain inet filter forward { policy drop; }'
```

`inet` covers IPv4 and IPv6 in one table. Dropping all ICMPv6 breaks IPv6 neighbour discovery, so the host loses IPv6 connectivity.

## 2. Make it persistent

Rules added with `nft` are lost at reboot. Save them to the file the `nftables` service loads:

```bash
nft list ruleset > /etc/nftables.conf     # Debian/Ubuntu path; RHEL uses /etc/sysconfig/nftables.conf
nft -c -f /etc/nftables.conf              # check syntax without applying
systemctl enable --now nftables
```

## 3. Inspect and audit

```bash
nft list ruleset -a                 # with rule handles (needed to delete one rule)
nft list chain inet filter input
nft delete rule inet filter input handle <handle>

# Legacy iptables view (want -P INPUT DROP)
iptables -S
ip6tables -S

# Front ends
ufw status verbose                  # "Default: deny (incoming)"
firewall-cmd --list-all             # zone, services, ports, rich rules
```

Log dropped packets for troubleshooting (rate-limited so logs are not flooded):

```bash
nft add rule inet filter input limit rate 5/minute log prefix '"nft-drop: "' level warn
journalctl -k -g 'nft-drop'
```

## 4. Security review

| Look for | Why |
| --- | --- |
| `policy accept` on input with no final drop rule | Default allow: every listening service is exposed |
| Accept rules from `0.0.0.0/0` / any for SSH, databases, admin panels | Limit sources to admin networks |
| Rules or tables nobody can explain | Attackers open ports for backdoors or remove drop rules |
| Empty IPv6 policy while IPv4 is locked down | Host is open over IPv6 |

→ [Host firewall default-deny assurance check](../../tasks/assurance/firewall-default-deny.md)

## Related

- [Firewall and Port Management](../../tasks/administration/firewall-port-management.md)
- [Linux networking](networking.md)

## Sources

- [nftables wiki — Quick reference](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [nft(8) manual](https://www.netfilter.org/projects/nftables/manpage.html)
- [Red Hat — Getting started with nftables](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_firewalls_and_packet_filters/getting-started-with-nftables_firewall-packet-filters)
