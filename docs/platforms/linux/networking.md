---
title: Linux Networking and DNS
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Troubleshooting, Administration]
category: Networking
tags: [ss, listening ports, network connections, dns, iptables, nftables, tcpdump, triage]
aliases: [listening ports linux, netstat linux, open ports, ss -lntp, dig, resolv.conf, firewall linux]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Linux Networking and DNS

`ss` (iproute2) replaces `netstat` (net-tools), which is not installed by default on many current distributions.

## Find listening ports

```bash
sudo ss -lntup
```

| Flag | Meaning |
| --- | --- |
| `-l` | listening sockets only |
| `-n` | numeric — do not resolve names/ports |
| `-t` / `-u` | TCP / UDP |
| `-p` | owning process (needs root to see other users' processes) |

```text
Netid State  Local Address:Port  Process
tcp   LISTEN 0.0.0.0:22          users:(("sshd",pid=812,fd=3))
tcp   LISTEN 127.0.0.1:5432      users:(("postgres",pid=1044,fd=6))
```

`0.0.0.0` / `[::]` = all interfaces; `127.0.0.1` = local only.

**What to look for:** shells or interpreters (`bash`, `sh`, `python`, `perl`, `nc`, `socat`) listening; listeners from `/tmp`, `/dev/shm` or deleted binaries; unexpected high ports.

Reusable tool: [`get-listening-ports.sh`](../../toolbox/bash.md#get-listening-portssh). Windows equivalent: [`Get-NetTCPConnection -State Listen`](../windows/networking.md#find-listening-ports).

## List established connections

```bash
sudo ss -tnp state established
sudo ss -tnp state established '( dport = :443 or sport = :443 )'
```

Alternative with `lsof`:

```bash
sudo lsof -i -P -n
```

## Find the process for a port

```bash
sudo ss -lntp 'sport = :8080'
sudo lsof -i :8080 -P -n
sudo fuser -v 8080/tcp
```

## IP addresses, routes and neighbours

```bash
ip -br address
ip route
ip neigh
```

## DNS lookups

```bash
dig example.com +short
dig @1.1.1.1 example.com A
dig -x '<TARGET_IP>' +short
getent hosts example.com
```

`dig` queries DNS directly. `getent hosts` follows the system's name-service order (`/etc/nsswitch.conf`), so it also honours `/etc/hosts` — use it to see what applications will actually resolve.

## Resolver configuration

```bash
resolvectl status              # systemd-resolved systems
cat /etc/resolv.conf
cat /etc/hosts
grep '^hosts:' /etc/nsswitch.conf
```

On systemd-resolved systems `/etc/resolv.conf` usually points at the stub `127.0.0.53`; the real upstream servers are shown by `resolvectl status`.

## Firewall rules

```bash
sudo nft list ruleset                # nftables (default backend on current distributions)
sudo iptables -S                     # iptables rules in command form
sudo ufw status verbose              # Ubuntu ufw front-end
sudo firewall-cmd --list-all         # RHEL/Fedora firewalld, active zone
```

Block an IP during containment (iptables syntax; not persistent across reboot):

```bash
sudo iptables -I INPUT -s '<TARGET_IP>' -j DROP
sudo iptables -I OUTPUT -d '<TARGET_IP>' -j DROP
```

## Test connectivity

```bash
nc -zv '<TARGET_HOST>' 443
curl -sv 'https://<TARGET_HOST>/' -o /dev/null
tracepath '<TARGET_HOST>'
```

## Capture packets

```bash
sudo tcpdump -i any -nn -c 100 port 53
sudo tcpdump -i eth0 -nn host '<TARGET_IP>' -w /tmp/case-target-ip.pcap
```

## Related

- [Network Investigation workflow](../../tasks/investigation/network-investigation.md)
- [Linux processes](processes.md)
- [Cross-platform equivalents](../../references/equivalents.md)

## Sources

- [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html)
- [ip(8)](https://man7.org/linux/man-pages/man8/ip.8.html)
- [resolvectl(1)](https://man7.org/linux/man-pages/man1/resolvectl.1.html)
