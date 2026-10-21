---
title: Assurance Check — Host Firewall Default Deny Stance
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-12
difficulty: basic
tags:
  - assurance
  - firewall
  - default-deny
---

# Assurance Check — Host Firewall Default Deny Stance

Verifies that Windows Defender Firewall and Linux `nftables`/`iptables` policies enforce a strict default inbound drop stance across all active network profiles.

**Why:** a default-allow host firewall exposes every listening service (SMB, RDP, WinRM, databases) to the whole network, which is how ransomware and worms move laterally. **Pass** = firewall on, default inbound is block/drop, and every inbound allow rule is explained. **Run as:** administrator / root; read-only.

## Windows

```powershell
# 1. Effective profile settings (ActiveStore = local settings merged with Group Policy)
Get-NetFirewallProfile -PolicyStore ActiveStore |
    ForEach-Object {
        $pass = $_.Enabled -and $_.DefaultInboundAction -eq 'Block'
        '{0,-6} {1,-8} Enabled={2} Inbound={3} Outbound={4}' -f $(if ($pass) { 'PASS' } else { 'FAIL' }),
            $_.Name, $_.Enabled, $_.DefaultInboundAction, $_.DefaultOutboundAction
    }

# 2. Enabled inbound allow rules that accept any remote address: review each one
Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True |
    Where-Object { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -contains 'Any' } |
    ForEach-Object {
        $port = $_ | Get-NetFirewallPortFilter
        [pscustomobject]@{
            Rule     = $_.DisplayName
            Profile  = $_.Profile
            Protocol = $port.Protocol
            Port     = $port.LocalPort
        }
    } | Sort-Object Rule | Format-Table -AutoSize
```

Workstations list hundreds of app rules here (Teams, browsers, games). Narrow the review by filtering the output on `Profile` (`Public`, `Any`) or on `Port` for remote-admin ports (135, 139, 445, 3389, 5985, 5986).

`DefaultInboundAction` of `NotConfigured` means the Windows default applies (block), but a Group Policy may set it later, so treat it as a finding to confirm. Check `Get-NetFirewallProfile -PolicyStore ActiveStore` rather than the local store: a GPO wins over local settings.

## Linux

Use the one that manages the host; mixing tools hides rules.

```bash
# nftables: every input chain and its policy (want "policy drop")
nft list ruleset | grep -E 'hook input'

# iptables (legacy or iptables-nft): want "-P INPUT DROP"
iptables -S INPUT | head -n 1
ip6tables -S INPUT | head -n 1

# ufw (Ubuntu): want "Default: deny (incoming)"
ufw status verbose

# firewalld (RHEL family): zones in use and their target (default rejects unmatched traffic)
firewall-cmd --get-active-zones
firewall-cmd --list-all
```

Do not forget **IPv6**: a host with `INPUT DROP` for IPv4 and an empty `ip6tables` policy is wide open over IPv6.

## Interpreting the results

| Finding | Risk | Action |
| --- | --- | --- |
| Firewall disabled on any profile | High | Enable through GPO / Intune; find out who disabled it (event 2003 in *Windows Firewall With Advanced Security/Firewall* log) |
| Default inbound allow / accept | High | Set block/drop; add explicit allow rules for required services |
| Allow rule from `Any` for SMB, RDP, WinRM, SSH | Medium | Restrict remote addresses to admin subnets or jump hosts |
| Unknown allow rule | Medium | Find the owning program; remove if unexplained (attackers add rules for C2 listeners) |

## Related

- [Per-service egress control](../hardening/per-service-egress-control.md)
- [Firewall and Port Management](../administration/firewall-port-management.md)
- [Windows Firewall](../../platforms/windows/firewall.md) · [Linux firewalls and nftables](../../platforms/linux/firewalls-nftables.md)
- [SMB Lateral Movement](../incident-response/smb-lateral-movement.md)

## Sources

- [Microsoft Learn — Get-NetFirewallProfile](https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallprofile)
- [nftables wiki — Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
- [CIS Benchmarks — host firewall sections (Windows, Linux)](https://www.cisecurity.org/cis-benchmarks)
