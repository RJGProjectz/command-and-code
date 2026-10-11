---
title: VPN & Remote Access Tunnel Troubleshooting
type: workflow
platforms: [Windows, Linux]
languages: [PowerShell, Bash, Windows CLI]
tasks: [Troubleshooting]
category: Workflow
tags: [workflow, troubleshooting, vpn, wireguard, globalprotect, ipsec, routing, dns, certs]
aliases: [vpn troubleshooting, vpn connected but no internet, global protect stuck connecting, wireguard handshake failed, vpn certificate mismatch]
difficulty: intermediate
verified: true
last_verified: 2026-10-08
---

# VPN & Remote Access Tunnel Troubleshooting

**Symptom:** a remote worker cannot connect to an enterprise VPN portal, the client stays stuck on "Connecting", traffic fails to route over the tunnel, or internal DNS resolution drops upon tunnel establishment.

---

## 1. Interactive Diagnostic Decision Tree

<div class="cc-tree" data-title="VPN & Remote Access Diagnostic Flow" markdown>

<div class="cc-node cc-node--root" data-id="step-portal-reach" markdown>

#### Step 1: External Gateway & Portal Reachability

Before inspecting client configurations or agent services, verify whether the client machine can resolve the gateway FQDN and establish TCP/UDP handshakes with the VPN portal:

```powershell
# 1. Test DNS resolution of VPN gateway
Resolve-DnsName -Name '<PORTAL_FQDN>'

# 2. Test SSL VPN control plane port (TCP 443)
Test-NetConnection -ComputerName '<PORTAL_FQDN>' -Port 443

# 3. Test IPsec encapsulation port reachability (UDP 4500 / 500)
Test-NetConnection -ComputerName '<PORTAL_FQDN>' -Port 4500
```

```bash
# Linux: Test WireGuard UDP endpoint reachability or SSL portal
nc -z -v -w 5 '<PORTAL_FQDN>' 443
nc -u -z -v -w 5 '<VPN_GATEWAY_IP>' 51820
```

**Can the client reach the gateway on port 443 / IPsec ports?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-agent-service">✓ Gateway Reachable (Port 443 open)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-gateway-unreachable">✗ Connection Timed Out / Dropped</button>
</div>

</div>

<div class="cc-node" data-id="step-gateway-unreachable" markdown>

#### Diagnostic Branch: Public Gateway / ISP Egress Block

The remote client cannot establish a socket with the VPN gateway.

1. **Test Public Internet Connectivity:**
   ```powershell
   Test-Connection -ComputerName 1.1.1.1 -Count 2
   ```
2. **Detect Hotel / Public Wi-Fi Captive Portals:**
   ```powershell
   # If HTTP 302 redirects are returned, the client is trapped behind a captive portal
   Invoke-WebRequest -Uri "http://www.msftconnecttest.com/connecttest.txt" -UseBasicParsing | Select-Object StatusCode, Content
   ```
3. **Inspect Local Firewall Outbound Drops:**
   ```powershell
   Get-NetFirewallRule -DisplayName "*VPN*" | Select-Object Name, Enabled, Direction, Action
   ```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-portal-reach">✓ Captive Portal Authenticated & Retest</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-agent-service" markdown>

#### Step 2: VPN Service & Virtual Network Adapter State

Verify that the local VPN service daemon is running and the virtual tunnel adapter (TAP/TUN, PanGPS, or WireGuard) is healthy:

```powershell
# Check Windows VPN services (GlobalProtect, WireGuard, Windows AOVPN)
Get-Service -Name "PanGPS", "WireGuardTunnel$*", "RasMan" -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

# Inspect virtual TAP/TUN network interfaces
Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Palo Alto|WireGuard|TAP|Virtual" } |
    Select-Object Name, InterfaceDescription, Status, LinkSpeed
```

```bash
# Linux: Check WireGuard kernel module and service status
sudo systemctl status wg-quick@wg0
sudo wg show
ip link show dev wg0
```

**Is the VPN service running and virtual adapter operational?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-cert-auth">✓ Service Running & Adapter Up</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-service-repair">✗ Service Stopped or Adapter Disabled</button>
</div>

</div>

<div class="cc-node" data-id="step-service-repair" markdown>

#### Diagnostic Branch: Service Restart & Adapter Reset

The local VPN service daemon has crashed, hung, or the virtual adapter driver failed to bind:

```powershell
# Restart PanGPS service (GlobalProtect)
Restart-Service -Name "PanGPS" -Force

# Enable virtual adapter if administratively disabled
Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Palo Alto|WireGuard" } | Enable-NetAdapter -Confirm:$false

# Run automated diagnostic and self-repair
.\scripts\powershell\FUNC_PS_TEST_VPN_CONNECTION.ps1 -Portal '<PORTAL_FQDN>' -Repair
```

```bash
# Linux: Restart WireGuard interface
sudo systemctl restart wg-quick@wg0
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-cert-auth">✓ Service Restored & Proceed</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-cert-auth" markdown>

#### Step 3: Machine & User Certificate Validation

Enterprise VPN solutions (Always On VPN, GlobalProtect with pre-logon, Cisco AnyConnect) authenticate endpoints using Active Directory Certificate Services (AD CS) machine certificates.

Inspect the local computer certificate store for valid machine authentication certificates:

```powershell
# Query Machine certificates enrolled for Client Authentication (EKU 1.3.6.1.5.5.7.3.2)
Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.EnhancedKeyUsageList.ObjectId -eq '1.3.6.1.5.5.7.3.2' } |
    Select-Object Subject, Issuer, NotBefore, NotAfter, HasPrivateKey, Thumbprint
```

**Does the machine have a valid, unexpired certificate with a private key?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-routing-split">✓ Valid Client Certificate Present</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-cert-missing">✗ Certificate Expired / Missing / No Private Key</button>
</div>

</div>

<div class="cc-node" data-id="step-cert-missing" markdown>

#### Diagnostic Branch: AD CS Certificate Re-Enrollment

The client machine failed auto-enrollment or the certificate has expired:

```powershell
# 1. Force Group Policy refresh to trigger auto-enrollment
gpupdate /force

# 2. Trigger auto-enrollment engine directly
certreq -pulse

# 3. Verify Intermediate and Root CA chains exist in Trusted Store
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA |
    Select-Object Subject, Issuer, NotAfter
```

*Remediation:* If auto-enrollment fails off-network, connect the machine via tethering or temporary bypass portal to allow initial Kerberos/RPC enrollment against the issuing CA.

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-routing-split">✓ Certificate Enrolled Successfully</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-routing-split" markdown>

#### Step 4: Routing Table & Split-Tunnel Validation

Once connected, verify that traffic destined for internal corporate subnets routes through the tunnel adapter rather than the local gateway:

```powershell
# Inspect active IPv4 routing table
Get-NetRoute -AddressFamily IPv4 |
    Where-Object { $_.DestinationPrefix -like "10.*" -or $_.DestinationPrefix -like "172.16.*" -or $_.DestinationPrefix -like "192.168.*" } |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# Test ICMP echo to internal gateway or DNS server
Test-Connection -ComputerName '<INTERNAL_DNS_IP>' -Count 2
```

```bash
# Linux: Verify routing table entries
ip route show
```

**Are internal subnet routes bound to the VPN interface?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-mtu-dns">✓ Routes Active & Internal Gateway Reachable</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-routing-conflict">✗ Subnet Missing or Metric Shadowed</button>
</div>

</div>

<div class="cc-node" data-id="step-routing-conflict" markdown>

#### Diagnostic Branch: Route Metric & Overlap Collision

A local LAN subnet collision (e.g., home router `192.168.1.0/24` overlapping corporate subnet `192.168.1.0/24`) or higher metric on the physical adapter is diverting tunnel traffic:

```powershell
# Inspect Interface Metrics
Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, InterfaceMetric

# Add temporary static route to internal resources through tunnel interface if omitted
New-NetRoute -DestinationPrefix '<INTERNAL_SUBNET>' -InterfaceAlias '<VPN_ADAPTER_ALIAS>' -RouteMetric 10
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-mtu-dns">✓ Route Corrected</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-mtu-dns" markdown>

#### Step 5: MTU Fragmentation & Split DNS Leaks

If tunnel connects but large payloads hang (e.g., Web apps spin, SSH connects but `cat large_file` freezes), diagnose MTU black holes and Name Resolution Policy Table (NRPT) rules:

```powershell
# 1. Test Path MTU without fragmentation
Test-Connection -ComputerName '<INTERNAL_HOST_IP>' -MtuSize 1472 -DontFragment -Count 1

# 2. Query Name Resolution Policy Table (NRPT) rules for internal domains
Get-DnsClientNrptRule

# 3. Test DNS resolution against corporate DNS server directly
Resolve-DnsName -Name '<INTERNAL_HOST>.<INTERNAL_DOMAIN>' -Server '<INTERNAL_DNS_IP>'
```

```bash
# Linux: Test Path MTU with ping do-not-fragment
ping -c 2 -M do -s 1400 '<INTERNAL_HOST_IP>'
```

**Does internal DNS resolve and MTU ping succeed?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ Resolved: VPN Fully Operational</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-mtu-fix">✗ MTU Packet Drop / DNS Leak Detected</button>
</div>

</div>

<div class="cc-node" data-id="step-mtu-fix" markdown>

#### Diagnostic Branch: Lower MTU & Flush DNS

Lower the MTU on the virtual adapter to prevent packet fragmentation over underlying encapsulation (ESP/WireGuard/TLS):

```powershell
# Lower MTU on VPN interface to 1360 or 1400
Set-NetIPInterface -InterfaceAlias '<VPN_ADAPTER_ALIAS>' -Nmtu 1360

# Flush local client resolver cache
Clear-DnsClientCache
```

```bash
# Linux: Lower WireGuard MTU
sudo ip link set dev wg0 mtu 1360
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ MTU Applied & Verified</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-resolved" markdown>

#### Resolution Confirmed

The VPN tunnel is established, authenticated via machine/user certificates, routing internal subnets with correct MTU, and resolving private DNS namespaces.

</div>

</div>

---

## 2. Automated Diagnostic Script

Execute the built-in Command & Code VPN testing utility to probe portal reachability, inspect PanGPS service health, audit AD CS certificates, and attempt automatic repair:

```powershell
# Run basic read-only diagnostic against portal
.\scripts\powershell\FUNC_PS_TEST_VPN_CONNECTION.ps1 -Portal '<PORTAL_FQDN>' -TargetEnvironment 'Prod'

# Run with automated service restart and DNS flush
.\scripts\powershell\FUNC_PS_TEST_VPN_CONNECTION.ps1 -Portal '<PORTAL_FQDN>' -Repair -TargetEnvironment 'Prod'
```

---

## 3. Quick Reference & Root Cause Matrix

| Operational Symptom | Primary Root Cause | Immediate Verification Command | Remediation Action |
| :--- | :--- | :--- | :--- |
| **Port 443 / 4500 Timeout** | Captive portal, public Wi-Fi block, or ISP filter | `Test-NetConnection '<PORTAL>' -Port 443` | Authenticate captive portal or switch to cellular hotspot. |
| **"Authentication Failed"** | AD CS client certificate expired or missing private key | `Get-ChildItem Cert:\LocalMachine\My` | Execute `certreq -pulse` or trigger `gpupdate /force`. |
| **PanGPS.exe Crashloop** | Stale socket or corrupted service configuration | `Get-Service PanGPS` | `Restart-Service PanGPS -Force` |
| **Connected but no intranet** | Local LAN subnet collision or wrong interface metric | `Get-NetRoute -AddressFamily IPv4` | Lower metric on VPN adapter via `Set-NetIPInterface`. |
| **Session freezes on large transfers** | Path MTU black hole (fragmentation blocked by DF bit) | `Test-Connection -MtuSize 1472 -DontFragment` | Lower adapter MTU to 1360: `Set-NetIPInterface -Nmtu 1360`. |
| **Internal hostnames fail to resolve** | Split-DNS leak; NRPT rule missing or unassigned | `Get-DnsClientNrptRule` | Ensure VPN profile applies DNS server and suffix search lists. |

---

## 4. Related Workflows & Tooling

- [Windows Connectivity Troubleshooting](windows-connectivity.md)
- [DNS Client Resolution and Troubleshooting](../administration/dns-resolution-troubleshooting.md)
- [WireGuard Secure VPN Gateway Deployment](../administration/wireguard-vpn-deployment.md)
- [PowerShell Toolbox — FUNC_PS_TEST_VPN_CONNECTION.ps1](../../toolbox/powershell.md)
