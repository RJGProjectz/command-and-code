---
title: Firewalls & Network Layer Controls
type: entry
platforms: [Linux, Windows, AWS, Azure, GCP]
languages: [Bash, PowerShell]
tasks: [Hardening, Assurance, Assessment]
category: Network Security
security_domain: Network
author: RJGProjectz
date_created: 2026-10-28
last_updated: 2026-10-28
tags: [firewall, iptables, nftables, ufw, windows-firewall, wfp, ngfw, vpc, security-groups, network-acl, egress-filtering, stateful-firewall, cloud-firewall]
aliases: [iptables hardening, nftables rules, UFW configuration, Windows Filtering Platform, cloud firewall, VPC security groups, Network ACL, NGFW, L7 firewall, stateful vs stateless firewall, host-based firewall]
difficulty: intermediate
verified: true
last_verified: 2026-10-28
---

# Firewalls & Network Layer Controls
> **Created**: 2026-10-28T00:00:00Z
> **Last Modified**: 2026-10-28T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Incorrect firewall rules can lock you out of a remote host.
> 1. Always ensure an out-of-band access path (console, serial, cloud recovery) exists before applying rules.
> 2. Test with `--dry-run` / `-n` (nftables) or in a VM snapshot first.
> 3. On cloud instances, apply rules in the correct order (default-allow → add-blocks is safer than default-deny with incremental allows).

Reference covering the fundamental differences between firewall types (L3/L4 stateful, L7 NGFW), host-based firewall implementations on Linux and Windows, and cloud-native network perimeter controls.

---

## 1. Firewall Taxonomy

### L3/L4 Stateful vs Stateless

| Dimension | Stateless (ACL) | Stateful (Connection-tracking) |
| :--- | :--- | :--- |
| **Inspection** | Matches individual packets: source/dest IP, protocol, port flags | Tracks connection state (SYN/ESTABLISHED/FIN); understands flows |
| **Return traffic** | Requires explicit rules for both directions | Automatically permits established return traffic |
| **Performance** | Fast: O(n) rule scan per packet | Slightly higher overhead; `conntrack` table consumes memory |
| **Use cases** | Router ACLs, AWS Network ACLs, raw iptables without state match | OS firewall (iptables -m state, nftables ct), cloud Security Groups |
| **Vulnerability** | ACK-scan bypass (packets with ACK set bypass TCP rules that only match SYN) | Conntrack table exhaustion (SYN flood can overflow state table) |

### L7 NGFW (Next-Generation Firewall)
An NGFW adds application-layer inspection above L3/L4:
- **Deep packet inspection (DPI)** — reassembles TCP streams and inspects application protocol data.
- **Application identification** — identifies the application regardless of port (Facebook over TCP/443 vs HTTPS).
- **TLS inspection** — man-in-the-middle decryption to inspect encrypted traffic (requires distributing a proxy CA certificate to clients).
- **Integrated IPS/IDS** — inline signature and anomaly detection.
- **User identity correlation** — maps firewall rules to Active Directory users via AD integration.

**NGFW vs WAF:** An NGFW is a network perimeter device; a WAF is application-aware and deployed inline to an HTTP server. They are complementary, not substitutes.

---

## 2. Linux Host-Based Firewalls

### iptables

iptables uses a table → chain → rule model. The most common tables:

| Table | Purpose | Default Chains |
| :--- | :--- | :--- |
| `filter` | Accept/drop packets | INPUT, FORWARD, OUTPUT |
| `nat` | Source/destination NAT | PREROUTING, POSTROUTING, OUTPUT |
| `mangle` | Modify packet headers (TTL, DSCP) | All chains |
| `raw` | Bypass conntrack | PREROUTING, OUTPUT |

**Minimal stateful web server ruleset:**

```bash
#!/usr/bin/env bash
# Flush all rules
iptables -F
iptables -X

# Default policy: drop everything
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT   # Outbound unrestricted; tighten with explicit OUTPUT rules

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections (stateful return traffic)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid packets (malformed/stale state)
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Allow SSH from management network only
iptables -A INPUT -p tcp --dport 22 -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP/HTTPS from anywhere
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT

# ICMP: allow echo-request with rate limit (ping)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s --limit-burst 10 -j ACCEPT

# Log and drop anything else
iptables -A INPUT -m limit --limit 10/min -j LOG --log-prefix "iptables-DROP: " --log-level 4
iptables -A INPUT -j DROP

# Save rules (Debian/Ubuntu)
iptables-save > /etc/iptables/rules.v4
```

**Inspect current rules:**
```bash
iptables -L INPUT -n -v --line-numbers
iptables -L -t nat -n -v
```

### nftables (modern replacement for iptables)

nftables unifies iptables, ip6tables, arptables, and ebtables into a single framework with atomic rule updates and set/map data structures.

```text
# /etc/nftables.conf
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # SSH — restrict to management VLAN
        ip saddr 10.0.1.0/24 tcp dport 22 ct state new accept

        # HTTP/HTTPS
        tcp dport { 80, 443 } ct state new accept

        # ICMP rate-limited
        icmp type echo-request limit rate 5/second accept
        icmpv6 type echo-request limit rate 5/second accept

        # Log and drop
        limit rate 10/minute log prefix "nft-DROP: " level warn
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

**Apply atomically (no temporary gap):**
```bash
nft -f /etc/nftables.conf    # Load/reload from file (atomic)
nft list ruleset              # Show all active rules
nft flush ruleset             # Clear all rules (careful: opens host)
```

**nftables sets for efficient IP block-listing:**
```text
table inet blocklist {
    set banned_ips {
        type ipv4_addr
        flags interval
        elements = { 1.2.3.0/24, 5.6.7.8 }
    }

    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @banned_ips drop
    }
}
```

### UFW (Uncomplicated Firewall)

UFW is a frontend over iptables/nftables, targeting Ubuntu/Debian servers that need simple rules without writing raw iptables.

```bash
# Enable UFW with default deny-inbound
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.0.1.0/24 to any port 22 proto tcp   # SSH from mgmt
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Status
ufw status verbose
ufw status numbered

# Delete a rule
ufw delete allow 80/tcp
```

**Gotcha:** `ufw enable` flushes iptables rules and rebuilds from UFW state. If you have existing manual iptables rules and enable UFW, those manual rules are lost unless you place them in `/etc/ufw/before.rules`.

---

## 3. Windows Filtering Platform (WFP) & Windows Firewall

Windows Filtering Platform is the kernel-level packet inspection framework underlying Windows Firewall, Windows Defender Firewall, and third-party host firewalls.

### Windows Firewall via PowerShell

```powershell
# View all active inbound rules
Get-NetFirewallRule -Direction Inbound -Enabled True | 
    Select-Object Name, DisplayName, Action, Profile |
    Format-Table -AutoSize

# Block inbound from specific IP
New-NetFirewallRule -DisplayName "Block-attacker" `
    -Direction Inbound -Action Block `
    -RemoteAddress 1.2.3.4 -Profile Any

# Allow a service on a specific interface
New-NetFirewallRule -DisplayName "Allow-NGINX-443" `
    -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 443 `
    -Profile Domain,Private

# Restrict a rule to a specific local service
New-NetFirewallRule -DisplayName "Allow-svc-out" `
    -Direction Outbound -Action Allow `
    -Protocol TCP -RemotePort 443 `
    -Service "wuauserv"   # Windows Update only; other processes blocked

# Remove a rule
Remove-NetFirewallRule -DisplayName "Block-attacker"
```

### Windows Firewall via netsh (legacy / scripting)

```cmd
netsh advfirewall firewall add rule ^
    name="Allow-HTTPS" dir=in action=allow ^
    protocol=TCP localport=443

netsh advfirewall show allprofiles state
```

### WFP key concepts

| Concept | Detail |
| :--- | :--- |
| **Profiles** | Domain, Private, Public — rules apply per profile; a laptop on public Wi-Fi uses stricter Public rules |
| **Filter engine** | Kernel-mode; runs at multiple WFP layers (FWPM_LAYER_INBOUND_TRANSPORT_V4 etc.) |
| **AppID filter** | Restrict traffic to a specific process path (`-Program "C:\nginx\nginx.exe"`) |
| **Dynamic rules** | Created at runtime by services; persist only while the service is running unless made permanent |

---

## 4. Cloud Network Perimeters

### AWS VPC Security Groups vs Network ACLs

| Dimension | Security Group | Network ACL |
| :--- | :--- | :--- |
| **Layer** | Stateful (L4+) | Stateless (L3/L4) |
| **Scope** | Applied to ENI (instance-level) | Applied to subnet |
| **Rule evaluation** | All rules evaluated; most-permissive match wins | Rules evaluated by rule number (lowest first); first match wins |
| **Inbound/Outbound** | Separate rules; return traffic implicit | Explicit rules for both directions |
| **Default** | Deny-all inbound, allow-all outbound | Allow-all (default NACL); a custom NACL starts deny-all |

**Minimal Security Group for a web tier:**
```bash
# Allow HTTPS from anywhere, SSH from bastion subnet only, all outbound
aws ec2 authorize-security-group-ingress \
    --group-id sg-0abc123def \
    --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress \
    --group-id sg-0abc123def \
    --protocol tcp --port 22 --source-group sg-bastion-id
```

### Azure Network Security Groups (NSG)

NSGs apply to NICs or subnets. Rules are evaluated by priority (100–4096; lower = evaluated first). Default rules allow VNet-inbound and internet-outbound; deny is by the lowest-priority default catch-all.

```bash
# Add a rule to allow HTTPS
az network nsg rule create \
    --resource-group myRG \
    --nsg-name myNSG \
    --name Allow-HTTPS \
    --priority 100 \
    --protocol Tcp \
    --direction Inbound \
    --source-address-prefixes "*" \
    --destination-port-ranges 443 \
    --access Allow

# View effective rules for an NIC
az network nic show-effective-nsg \
    --resource-group myRG \
    --name myNIC \
    --output table
```

### Egress Filtering

Uncontrolled egress allows:
- Data exfiltration to attacker-controlled domains.
- C2 beaconing over HTTP/DNS.
- SSRF pivot to external services.

**Egress controls by platform:**

| Platform | Control | Example |
| :--- | :--- | :--- |
| Linux | nftables OUTPUT chain; HTTP/HTTPS through a proxy (`http_proxy=`) | `tcp dport 443 ip daddr != 10.0.0.0/8 drop` |
| Windows | Windows Firewall outbound rules + proxy enforcement via GPO | `New-NetFirewallRule -Direction Outbound -Action Block -RemotePort 80,443 -Program "System"` |
| AWS | VPC endpoint (Private Link) for AWS services; NAT Gateway + Security Group egress restriction | Restrict SG outbound to known destination CIDR |
| Azure | Azure Firewall + forced tunneling; NSG outbound rules + Service Endpoints | Force tunnel default route to Azure Firewall; allow only approved FQDNs |

---

## 5. Verification Checklist

```bash
# Linux — confirm default-drop policy active
iptables -L INPUT -n | head -3
# or
nft list table inet filter | grep "policy"

# Test that a blocked port is unreachable
nc -zv 127.0.0.1 23 2>&1    # Should: Connection refused or timeout

# Windows — list active inbound rules
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
    Select-Object DisplayName, LocalPort | Sort-Object LocalPort

# Cloud — audit Security Group inbound rules for over-permissive 0.0.0.0/0 on sensitive ports
aws ec2 describe-security-groups --output json | \
    jq -r '.SecurityGroups[] | select(.IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0") | .GroupId + " " + .GroupName'
```

---

## Related

- [NGINX Web Server Hardening](../../tasks/hardening/nginx-web-server-hardening.md)
- [Web Server & Reverse Proxy Hardening](../../tasks/hardening/web-server-reverse-proxy-hardening.md)
- [Windows Firewall & Audit Policy](../../platforms/windows/firewall.md)
- [Azure NSG Compliance](../../tasks/assurance/azure-nsg-compliance.md)
- [WAF Fundamentals & Tuning](../../tasks/hardening/waf-fundamentals-and-tuning.md)
- [Defense in Depth](../../fundamentals/concepts/defense-in-depth.md)
- [OSI Model & TCP/IP](../../fundamentals/concepts/osi-model-tcp.md)

## External Resources & White Papers

- [nftables Wiki — Netfilter](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [Windows Firewall with Advanced Security — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)
- [AWS Security Groups vs NACLs](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-connection-tracking.html)
- [Azure NSG Documentation](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [CIS Linux Benchmarks — Network Configuration](https://www.cisecurity.org/benchmark/ubuntu_linux)
