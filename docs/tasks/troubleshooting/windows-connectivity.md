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

<div class="cc-tree" data-title="Interactive Connectivity Triage Flow" markdown>

<div class="cc-node cc-node--root" data-id="step-dns" markdown>

#### Step 1: DNS Resolution Check

Can the client resolve the destination hostname to an IP address?

```powershell
Resolve-DnsName -Name '<TARGET_HOST>.<INTERNAL_DOMAIN>'
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-route">✓ Resolved Successfully</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-dns-failure">✗ NXDOMAIN / Timeout</button>
</div>

</div>

<div class="cc-node" data-id="step-dns-failure" markdown>

#### Diagnostic Branch: DNS Resolution Failure

The host cannot resolve the domain name. Query the authoritative DC directly and check local DNS server assignments:

```powershell
# 1. Query client DNS adapter configuration
Get-DnsClientServerAddress -AddressFamily IPv4

# 2. Test lookup directly against internal DNS server
Resolve-DnsName -Name '<TARGET_HOST>.<INTERNAL_DOMAIN>' -Server '<DNS_SERVER_IP>'

# 3. Flush local resolver cache
Clear-DnsClientCache
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-route">✓ Resolved via Direct DNS Server</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-route" markdown>

#### Step 2: Gateway & IP Routing Verification

Verify layer 3 routing path and gateway reachability to the destination host:

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -TraceRoute
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-port">✓ Route Hops Reachable</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-route-failure">✗ Routing Failed / Gateway Drop</button>
</div>

</div>

<div class="cc-node" data-id="step-route-failure" markdown>

#### Diagnostic Branch: Gateway Routing Failure

Packets are dropped before reaching the destination subnet. Check default route and ARP resolution:

```powershell
# 1. Inspect active routing table and interface metric
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric

# 2. Check ARP neighbor table for default gateway
Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' }
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-port" markdown>

#### Step 3: TCP Port Reachability

Test whether the target service TCP port is accessible through network firewalls:

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -Port 443
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-app-layer">✓ TcpTestSucceeded : True</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-port-blocked">✗ TcpTestSucceeded : False</button>
</div>

</div>

<div class="cc-node" data-id="step-port-blocked" markdown>

#### Diagnostic Branch: Port Blocked or Service Inactive

If ping succeeds but the TCP port test fails, the issue is either host firewall or service state on the server:

```powershell
# Run on the SERVER:
# 1. Verify service is listening on all interfaces (0.0.0.0, not 127.0.0.1)
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 443 }

# 2. Verify Windows Defender Firewall inbound rule is active
Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object { $_.Enabled -eq $true }
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-app-layer" markdown>

#### Diagnostic Branch: Application & TLS Layer Triage

Network connectivity and TCP socket are verified. Troubleshoot TLS handshake, authentication, or service health:

```powershell
# 1. Test TLS Handshake and examine remote SSL certificate
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$Req = [Net.HttpWebRequest]::Create("https://<TARGET_HOST>")
$Req.GetResponse()
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-dns">✓ Triage Complete</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

</div>

---

## Detailed Step Reference

### 1. Does the name resolve correctly?

```powershell
Resolve-DnsName -Name '<TARGET_HOST>.<INTERNAL_DOMAIN>'
Resolve-DnsName -Name '<TARGET_HOST>.<INTERNAL_DOMAIN>' -Server '<DNS_SERVER_IP>'
```

Compare with `hosts` and the DNS cache. → [DNS lookups](../../platforms/windows/networking.md#dns-lookups)

### 2. Is there a route?

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -TraceRoute
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric
```

### 3. Is the port open from the client?

```powershell
Test-NetConnection -ComputerName '<TARGET_HOST>' -Port 443
```

`TcpTestSucceeded : False` with ping succeeding → firewall or service problem.

### 4. Is the service listening on the server?

→ [Find listening ports](../../platforms/windows/networking.md#find-listening-ports)

Listening only on `127.0.0.1` explains "works locally, not remotely".

### 5. Is the server firewall allowing it?

→ [List inbound allow rules](../../platforms/windows/firewall.md#list-enabled-inbound-allow-rules-with-ports) · [Enable logging](../../platforms/windows/firewall.md#enable-firewall-logging) and read `pfirewall.log` for `DROP`

### 6. Is a network firewall or proxy in the path?

Test from a host on the same subnet as the server. If that works, the problem is between subnets.

### 7. TLS, authentication, time

Certificate expiry or name mismatch, Kerberos failures from clock skew (`w32tm /query /status`), service account lockouts.

→ [Windows troubleshooting commands](../../platforms/windows/troubleshooting.md)
