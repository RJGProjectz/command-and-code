---
title: Windows Connectivity Troubleshooting
type: workflow
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Troubleshooting]
category: Workflow
tags: [workflow, troubleshooting, connectivity, dns, firewall, port]
aliases: [cannot connect to server, port not reachable, dns not resolving, troubleshoot network windows]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Connectivity Troubleshooting

**Symptom:** a client cannot reach a service on a server.

Work from the bottom of the stack up, and test from **both ends**.

## 1. Does the name resolve correctly?

```powershell
Resolve-DnsName -Name '<TARGET_HOST>.<INTERNAL_DOMAIN>'
Resolve-DnsName -Name '<TARGET_HOST>.<INTERNAL_DOMAIN>' -Server '<DNS_SERVER_IP>'
```

Compare with `hosts` and the DNS cache. → [DNS lookups](../../platforms/windows/networking.md#dns-lookups)

## 2. Is there a route?

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -TraceRoute
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric
```

## 3. Is the port open from the client?

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -Port 443
```

`TcpTestSucceeded : False` with ping succeeding → firewall or service problem.

## 4. Is the service listening on the server?

→ [Find listening ports](../../platforms/windows/networking.md#find-listening-ports)

Listening only on `127.0.0.1` explains "works locally, not remotely".

## 5. Is the server firewall allowing it?

→ [List inbound allow rules](../../platforms/windows/firewall.md#list-enabled-inbound-allow-rules-with-ports) · [Enable logging](../../platforms/windows/firewall.md#enable-firewall-logging) and read `pfirewall.log` for `DROP`

## 6. Is a network firewall or proxy in the path?

Test from a host on the same subnet as the server. If that works, the problem is between subnets.

## 7. TLS, authentication, time

Certificate expiry or name mismatch, Kerberos failures from clock skew (`w32tm /query /status`), service account lockouts.

→ [Windows troubleshooting commands](../../platforms/windows/troubleshooting.md)
