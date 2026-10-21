---
title: Restrict Outbound Traffic per Service (Windows Firewall, nftables, systemd)
type: workflow
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, Bash]
tasks: [Hardening, Administration]
category: Workflow
security_domain: Network
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [egress, outbound-firewall, service-hardening, windows-firewall, nftables, systemd, cgroup, least-privilege, exfiltration]
aliases: [per service egress, service outbound allowlist, New-NetFirewallRule -Service, Get-NetFirewallServiceFilter, windows service hardening firewall, sc qsidtype, nft meta skuid, nft socket cgroupv2, IPAddressAllow, IPAddressDeny, RestrictAddressFamilies, RestrictNetworkInterfaces, SocketBindDeny, PrivateNetwork, event 5157 filtering platform]
difficulty: advanced
verified: true
last_verified: 2026-10-20
---

# Restrict Outbound Traffic per Service (Windows Firewall, nftables, systemd)
> **Created**: 2026-10-20T19:10:00Z
> **Last Modified**: 2026-10-20T19:10:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Egress rules that are too tight break updates, DNS, time sync, licensing and monitoring agents. List
> what the service really talks to first (section 1), apply the rules on one test host, and keep a
> console (not SSH or RDP through the same rules) open while you test. Use `-WhatIf` on every
> `New-NetFirewallRule`, and `nft -c -f` to check a ruleset before you load it.

**Trigger:** a service account is least-privilege on disk ([Linux](../administration/linux-service-accounts-least-privilege.md),
[Windows](../administration/windows-service-accounts-least-privilege.md)), but its process can still
open a connection to any address on the internet.

**Goal:** each service reaches only its own endpoints (database, API, DNS, update server), so a
compromised service cannot download tools, reach a C2 server or send data out.

| Platform | Matches traffic by | Tool | Section |
| :--- | :--- | :--- | :--- |
| Windows | service SID | `New-NetFirewallRule -Service` | 2-3 |
| Linux | socket owner UID | nftables `meta skuid` | 4 |
| Linux | systemd unit cgroup | nftables `socket cgroupv2` | 4 |
| Linux | systemd unit cgroup (eBPF) | `IPAddressAllow=`, `IPAddressDeny=`, `RestrictAddressFamilies=` | 5 |

## 1. List what the service talks to

Watch the service for a normal business cycle before you write rules.

```powershell
# Windows: remote endpoints by process (services in svchost share a PID; see the Service column)
$svcByPid = Get-CimInstance Win32_Service | Where-Object ProcessId -gt 0 | Group-Object ProcessId -AsHashTable -AsString
Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -notin '127.0.0.1', '::1' } |
    Select-Object OwningProcess, RemoteAddress, RemotePort,
        @{ Name = 'Service'; Expression = { ($svcByPid["$($_.OwningProcess)"]).Name -join ',' } } |
    Sort-Object Service, RemoteAddress -Unique
```

```bash
# Linux: remote endpoints of one unit's processes (ss -p shows pid; match against the unit's cgroup)
unit=myapp.service
pids=$(tr '\n' '|' < "/sys/fs/cgroup/system.slice/$unit/cgroup.procs"); pids=${pids%|}
ss -tunp state established | grep -E "pid=($pids)," | awk '{print $1, $5}' | sort -u   # protocol, peer
```

Write the result as an allowlist: destination address or subnet, protocol, port, reason. Include DNS
(or the local resolver), NTP, the update source, the log or EDR collector, and any license server.

## 2. Windows: rules bound to a service

`New-NetFirewallRule -Service` takes the service **short name** (`Get-Service` `Name`, not
`DisplayName`) and matches traffic sent by that service, even inside a shared `svchost.exe`. The
firewall identifies the service by its **service SID**, so the SID type must not be `NONE`:

```powershell
sc.exe qsidtype MyAppSvc                         # SERVICE_SID_TYPE: UNRESTRICTED or RESTRICTED
sc.exe sidtype  MyAppSvc unrestricted            # if it says NONE; takes effect after a service restart
```

**Block wins over allow** in Windows Firewall. An allow rule alone does not stop anything while the
profile's default outbound action is `Allow`, and a "block everything" rule for the service would also
beat its allow rules. Pick one of two patterns.

**Pattern A - one service, default outbound stays Allow:** a block rule for the service that lists
every address **except** its allowlist, as ranges. Example: `MyAppSvc` may reach only `10.20.0.0/16`.

```powershell
$svc = 'MyAppSvc'
New-NetFirewallRule -DisplayName "Egress block $svc (outside allowlist)" -Group 'Service egress' `
    -Direction Outbound -Action Block -Service $svc -Profile Any `
    -RemoteAddress '0.0.0.0-10.19.255.255', '10.21.0.0-126.255.255.255', '128.0.0.0-255.255.255.255',
                   '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' -WhatIf
```

The ranges skip `10.20.0.0/16` and `127.0.0.0/8`; the last range blocks all IPv6 for the service.
Narrow the allowed hole further with `-RemotePort` on a second block rule if the service must reach
only one port in that subnet.

**Pattern B - servers with default outbound Block:** allow rules per service and per system
component, then switch the profile's default. This is stronger (new programs get nothing) but you must
first allow everything the OS needs (DNS client, Windows Update, time, domain controllers, the EDR).

```powershell
New-NetFirewallRule -DisplayName "Egress allow MyAppSvc -> DB" -Group 'Service egress' `
    -Direction Outbound -Action Allow -Service 'MyAppSvc' -Protocol TCP `
    -RemoteAddress '10.20.5.10' -RemotePort 1433 -Profile Domain -WhatIf

# Only after every needed allow rule exists, and from a console session:
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Block -WhatIf
```

See [Manage host firewall and ports](../administration/firewall-port-management.md) for profile basics
and [Firewall default deny](../assurance/firewall-default-deny.md) to audit the profile defaults.

## 3. Windows: review and log

```powershell
# All rules bound to a service, with their address and port filters
Get-NetFirewallServiceFilter | Where-Object Service -ne 'Any' | ForEach-Object {
    $rule = $_ | Get-NetFirewallRule
    $addr = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    [pscustomobject]@{
        Service = $_.Service; Name = $rule.DisplayName; Direction = $rule.Direction; Action = $rule.Action
        Enabled = $rule.Enabled; RemoteAddress = $addr.RemoteAddress -join ','; Protocol = $port.Protocol
        RemotePort = $port.RemotePort -join ','
    }
} | Sort-Object Service, Direction | Format-Table -AutoSize
```

Log blocked connections, then read them (event **5157**, *The Windows Filtering Platform has blocked a
connection*; the event shows the application path, destination address and port):

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157 } -MaxEvents 50 |
    Select-Object TimeCreated, Message
```

5157 is noisy on busy hosts; enable it during rollout or forward only the hosts you are tightening.
The firewall's own log (`Set-NetFirewallProfile -LogBlocked True`) is an alternative.

## 4. Linux: nftables by UID or cgroup

Give each service its own system user ([Linux service accounts](../administration/linux-service-accounts-least-privilege.md)),
then match on the **socket owner** in the `output` hook. `meta skuid` takes a user name or UID.
`socket cgroupv2 level N "path"` matches the socket's cgroup path under `/sys/fs/cgroup`; level 2
matches `system.slice/<unit>`.

```text
# /etc/nftables.d/egress-services.nft  (include it from /etc/nftables.conf)
table inet svc_egress {
    set myapp_allow4 {
        type ipv4_addr . inet_service
        elements = { 10.20.5.10 . 5432, 10.20.9.20 . 443 }
    }

    chain output {
        type filter hook output priority filter; policy accept;
        oifname "lo" accept
        ct state established,related accept

        # by user: everything the myapp account sends must match the set
        meta skuid "myapp" udp dport 53 ip daddr 10.20.0.53 accept
        meta skuid "myapp" ip daddr . tcp dport @myapp_allow4 accept
        meta skuid "myapp" counter log prefix "egress-deny myapp " drop

        # by systemd unit (cgroup v2): only HTTPS to the update mirror
        socket cgroupv2 level 2 "system.slice/updater.service" ip daddr 10.20.9.30 tcp dport 443 accept
        socket cgroupv2 level 2 "system.slice/updater.service" counter drop
    }
}
```

```bash
nft -c -f /etc/nftables.d/egress-services.nft        # syntax check only, changes nothing
nft -f /etc/nftables.d/egress-services.nft
nft list chain inet svc_egress output                 # counters show matches and drops
journalctl -k -g 'egress-deny' --since '-1h'          # logged drops
```

- `meta skuid` matches only locally created sockets (output hook), and only processes running as that
  user. A service that runs as `root` cannot be separated this way; fix the account first.
- `socket cgroupv2` needs the cgroup to exist when the rule is loaded: start the unit before you load
  the rules. The kernel compares cgroup IDs, so a rule can stop matching after the unit's cgroup is
  removed and recreated (unit stop/start); reload the ruleset after such restarts (for example from
  an `ExecStartPost=` drop-in) or prefer `meta skuid` or section 5.
- Keep IPv6 in mind: `inet` tables see both families; add an `ip6 daddr` set or drop IPv6 for the user.

## 5. Linux: systemd unit sandbox

systemd applies these in the unit's cgroup with eBPF, so they follow the service across restarts with
no firewall rules. `IPAddressAllow=` wins: an address that matches it is allowed, otherwise a match in
`IPAddressDeny=` is denied, otherwise allowed. Both directions are filtered (egress checks the
destination). Special values: `any`, `localhost`, `link-local`, `multicast`.

```ini
# systemctl edit myapp.service  ->  /etc/systemd/system/myapp.service.d/egress.conf
[Service]
IPAddressDeny=any
IPAddressAllow=localhost 10.20.5.10 10.20.9.20 10.20.0.53
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNetworkInterfaces=eth0
SocketBindDeny=any
```

```bash
systemctl daemon-reload && systemctl restart myapp.service
systemctl show myapp.service -p IPAddressAllow -p IPAddressDeny -p RestrictAddressFamilies
systemd-analyze security myapp.service | grep -E 'IPAddress|AddressFamilies|PrivateNetwork'
```

- Filtering is by address only, not by port or name. Allow the DNS server (or `localhost` for
  `systemd-resolved` at `127.0.0.53`) or the service cannot resolve names.
- `RestrictAddressFamilies=` blocks socket types (for example `AF_PACKET` raw sockets, `AF_NETLINK`).
- `SocketBindDeny=any` stops the service from listening on new ports; add `SocketBindAllow=tcp:8443`
  for its own listener. Rules use `[family:][protocol:][port or range]`.
- A service with no network needs at all gets `PrivateNetwork=yes` (loopback only).
- Combine with section 4 when you also need port-level egress rules.

## 6. Verify

- [ ] The allowlist from section 1 is written down with an owner and a reason per entry.
- [ ] From the service's context, an allowed endpoint works and a disallowed one fails: Windows
      `Test-NetConnection` does not run as the service, so check event **5157** after a real request;
      Linux `sudo -u myapp curl -m5 https://example.org` (UID rules) or
      `systemd-run -p IPAddressDeny=any -p IPAddressAllow=10.20.5.10 --pty curl ...` (unit settings).
- [ ] `nft list chain inet svc_egress output` shows drop counters only for the denied tests.
- [ ] The service still passes its health check after a restart and after a reboot.
- [ ] Rules are in configuration management (GPO, `/etc/nftables.d/`, unit drop-ins), not only on the
      host.

ATT&CK relevance: per-service egress limits **T1071** (application layer C2), **T1105** (ingress tool
transfer) and **T1041/T1567** (exfiltration over C2 or web services) from a compromised service; the
5157 and nft log lines give detection for **T1571** (non-standard port) attempts.

## Related

- [Linux service accounts with least privilege](../administration/linux-service-accounts-least-privilege.md)
- [Windows service accounts with least privilege](../administration/windows-service-accounts-least-privilege.md)
- [Manage host firewall and ports](../administration/firewall-port-management.md)
- [Firewall default deny](../assurance/firewall-default-deny.md)
- [Linux CIS filesystems and services](linux-cis-filesystem-services.md)

## Sources

- [New-NetFirewallRule](https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule)
- [Get-NetFirewallServiceFilter](https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallservicefilter)
- [Audit Filtering Platform Connection (5157)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157)
- [nft(8) manual](https://www.netfilter.org/projects/nftables/manpage.html)
- [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
