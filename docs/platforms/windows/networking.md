---
title: Windows Networking and DNS
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Troubleshooting, Administration]
category: Networking
tags: [tcp, udp, ports, listening ports, network connections, dns, smb, netstat, triage]
aliases: [listening ports, open ports, netstat, network connections, established connections, dns cache, nslookup, Test-NetConnection]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Windows Networking and DNS

## Find listening ports

```powershell
Get-NetTCPConnection -State Listen |
    Sort-Object LocalPort |
    Select-Object LocalAddress, LocalPort, OwningProcess,
        @{ Name = 'Process'; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
```

UDP has no "listening" state — list bound endpoints instead:

```powershell
Get-NetUDPEndpoint | Sort-Object LocalPort | Select-Object LocalAddress, LocalPort, OwningProcess
```

**Windows CLI:**

```text
netstat -ano | findstr LISTENING
netstat -anob        (elevated: includes the executable name)
```

**What the output tells you**

| LocalAddress | Meaning |
| --- | --- |
| `0.0.0.0` / `::` | Listening on all interfaces — reachable from the network unless the firewall blocks it |
| `127.0.0.1` / `::1` | Local only |
| Specific IP | Bound to one interface |

**What to look for:** unexpected high ports, listeners owned by processes in user-writable paths, remote-access tools (VNC 5900, AnyDesk, TeamViewer), unexpected RDP (3389), WinRM (5985/5986) or SMB (445) exposure on workstations.

Reusable tool: [`Get-ListeningPorts.ps1`](../../toolbox/powershell.md#get-listeningports). Linux equivalent: [`ss -lntup`](../linux/networking.md#find-listening-ports).

## List established connections

```powershell
Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -notin '127.0.0.1', '::1' } |
    Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{ Name = 'Process'; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path } } |
    Sort-Object RemoteAddress
```

**What to look for:** scripting engines (`powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`) with external connections, connections to rare countries/ASNs, many connections to one IP on an unusual port.

!!! note "Point in time"
    This is a snapshot. Short-lived beacons are easy to miss — use EDR/SIEM telemetry ([KQL network events](../../detection/kql/network-events.md)) for history.

## IP configuration, routes and ARP

```powershell
Get-NetIPConfiguration
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric
Get-NetNeighbor -AddressFamily IPv4 | Where-Object State -ne 'Unreachable'
```

**Windows CLI:** `ipconfig /all`, `route print`, `arp -a`.

## DNS lookups

```powershell
Resolve-DnsName -Name example.com -Type A
Resolve-DnsName -Name example.com -Type MX -Server 1.1.1.1
Resolve-DnsName -Name '<TARGET_IP>' -Type PTR
```

`-Server` bypasses the configured resolver — useful for comparing internal and public answers.

## DNS client cache

Shows names this host resolved recently — useful for spotting C2 domains after the connection has closed.

```powershell
Get-DnsClientCache | Select-Object Entry, RecordName, Data, TimeToLive | Sort-Object Entry
```

**Windows CLI:** `ipconfig /displaydns`. Clear with `Clear-DnsClientCache` or `ipconfig /flushdns` — **after** collecting it.

## DNS servers and hosts file

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses
Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
```

A modified `hosts` file redirecting security or update domains is a classic tampering indicator.

## Test connectivity to a port

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -Port 443
Test-NetConnection -ComputerName '<TARGET_HOST>' -TraceRoute
```

`TcpTestSucceeded : True` means a TCP handshake completed. In PowerShell 7 `Test-Connection -TargetName '<TARGET_HOST>' -TcpPort 443` is a faster alternative.

## SMB shares, sessions and connections

```powershell
Get-SmbShare                 # shares this host offers
Get-SmbSession               # who is connected to this host (elevated)
Get-SmbConnection            # shares this host is connected to
```

**Windows CLI:** `net share`, `net session`, `net use`.

**Security relevance:** inbound SMB sessions from workstations to workstations, or admin shares (`C$`, `ADMIN$`) accessed by unexpected accounts, are lateral-movement indicators. See [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md).

## Proxy configuration

```text
netsh winhttp show proxy
```

User (WinINET) proxy settings live in `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`).

## Related

- [Windows Firewall](firewall.md)
- [Network Investigation workflow](../../tasks/investigation/network-investigation.md)
- [Suspicious Outbound Connection workflow](../../tasks/investigation/suspicious-outbound-connection.md)
- [Cross-platform equivalents](../../references/equivalents.md)

## Sources

- [Get-NetTCPConnection](https://learn.microsoft.com/powershell/module/nettcpip/get-nettcpconnection)
- [Resolve-DnsName](https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname)
- [Test-NetConnection](https://learn.microsoft.com/powershell/module/nettcpip/test-netconnection)
