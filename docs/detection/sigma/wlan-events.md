---
title: Detection Rules — Wi-Fi (WLAN-AutoConfig and Unknown Devices)
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - Sigma
  - KQL
  - SPL
tasks:
  - Detection Engineering
  - Investigation
verified: false
difficulty: intermediate
tags:
  - wifi
  - wlan
  - wlan-autoconfig
  - deauthentication
  - evil-twin
  - dhcp
  - 8003
---

# Detection Rules — Wi-Fi (WLAN-AutoConfig and Unknown Devices)

Three Wi-Fi detections from logs you already have: disconnect bursts on Windows clients (deauthentication attacks),
WLAN-AutoConfig connection analysis (evil-twin downgrades), and new devices leasing addresses on the wireless subnet.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The `Microsoft-Windows-WLAN-AutoConfig/Operational` channel is **not** collected by default by Windows Event
    Forwarding, the Azure Monitor Agent or the Splunk UF — add it to your collection rule first. Field names inside
    the event (`SSID`, `Reason`, `AuthenticationAlgorithm`) vary by Windows build; check one raw event.
    Roaming, sleep and driver bugs also cause disconnects — thresholds are placeholders.

- **Concepts**: [Wi-Fi Security](../../fundamentals/concepts/wifi-security.md) · [Wi-Fi Deauth & Rogue AP](../../fundamentals/concepts/wifi-deauth-rogue-ap.md) · [Wi-Fi Passphrase Attacks](../../fundamentals/concepts/wifi-passphrase-attacks.md)
- **ATT&CK**: [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) (evil twin)

## WLAN-AutoConfig events used

| Event ID | Meaning |
| :--- | :--- |
| 8001 | Connected to a wireless network (SSID, authentication, encryption) |
| 8002 | Failed to connect (reason code) |
| 8003 | Disconnected from a wireless network (reason) |

Full reason-code list: [WLAN_REASON_CODE](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-reason-code).
On one laptop, `netsh wlan show wlanreport` builds an HTML timeline of the same events.

## 1. Disconnect bursts (deauthentication)

A deauth attack forces every client in range off the AP repeatedly. One laptop disconnecting is noise; **several hosts
on the same SSID disconnecting many times in the same few minutes** is the signal.

```yaml
title: Wi-Fi Disconnect Burst on Windows Client
id: c14637a9-e436-47d8-a229-c53d62019838
name: wlan_disconnect
status: experimental
description: Base rule - WLAN-AutoConfig disconnect events.
author: RJGProjectz
date: 2026-10-11
logsource:
  product: windows
  service: wlan-autoconfig   # custom service mapping to Microsoft-Windows-WLAN-AutoConfig/Operational
detection:
  selection:
    EventID: 8003
  condition: selection
level: informational
---
title: Wi-Fi Disconnect Burst Across Hosts
id: be9d1697-9515-49df-ab6f-5437950f6033
status: experimental
description: Disconnects from three or more distinct hosts on the same SSID within five minutes.
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.impact
correlation:
  type: value_count
  rules:
    - wlan_disconnect
  group-by:
    - SSID
  timespan: 5m
  condition:
    field: Computer
    gte: 3
falsepositives:
  - AP reboot, firmware update or controller failover
  - Building-wide power or switch outage
level: medium
```

```kql
Event
| where EventLog == "Microsoft-Windows-WLAN-AutoConfig/Operational" and EventID == 8003
| extend SSID = extract(@"SSID: ([^\r\n]+)", 1, RenderedDescription),
         Reason = extract(@"Reason: ([^\r\n]+)", 1, RenderedDescription)
| summarize Disconnects = count(), Hosts = dcount(Computer), Reasons = make_set(Reason, 5)
    by SSID, bin(TimeGenerated, 5m)
| where Disconnects >= 10 and Hosts >= 3
```

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-WLAN-AutoConfig/Operational" EventCode=8003
| bin _time span=5m
| stats count as disconnects dc(host) as hosts values(Reason) as reasons by _time, SSID
| where disconnects >= 10 AND hosts >= 3
```

## 2. WLAN-AutoConfig connection analysis (evil twin)

An evil twin usually copies the SSID but not the security. A corporate SSID that is normally WPA2/WPA3-Enterprise
showing up in an 8001 with **Open** or **WPA2-Personal** authentication means a client joined a look-alike AP.

```yaml
title: Corporate SSID Joined with Unexpected Authentication
id: 5e82ff49-fb64-4990-81d9-081f5956b717
status: experimental
description: Detects a successful connection to a corporate SSID using open or pre-shared-key authentication.
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.credential-access
  - attack.t1557
logsource:
  product: windows
  service: wlan-autoconfig
detection:
  selection:
    EventID: 8001
    SSID:
      - 'CORP-WIFI'           # your enterprise SSIDs
  expected_auth:
    AuthenticationAlgorithm|contains:
      - 'WPA2-Enterprise'
      - 'WPA3-Enterprise'
  condition: selection and not expected_auth
falsepositives:
  - A guest or lab SSID that reuses the corporate name
level: high
```

```kql
Event
| where EventLog == "Microsoft-Windows-WLAN-AutoConfig/Operational" and EventID == 8001
| extend SSID = extract(@"SSID: ([^\r\n]+)", 1, RenderedDescription),
         Auth = extract(@"Authentication: ([^\r\n]+)", 1, RenderedDescription)
| where SSID in ("CORP-WIFI") and Auth !has "Enterprise"
| project TimeGenerated, Computer, SSID, Auth
```

Also hunt 8002 failures with an authentication reason on the corporate SSID — a client rejecting a rogue AP's
certificate leaves those.

## 3. Unknown device on the WLAN

A cracked passphrase lets an attacker join as a new device. Compare every new DHCP lease on the wireless scope with
your device inventory. Windows DHCP Server writes leases to `%windir%\System32\dhcp\DhcpSrvLog-*.log` (CSV; ID `10` = new lease).

```spl
index=dhcp sourcetype=DhcpSrvLog ID=10 ip="10.20.*"
| lookup known_devices mac AS mac OUTPUT owner
| where isnull(owner)
| stats earliest(_time) as first_seen values(ip) as ips values(hostname) as hostnames by mac
| convert ctime(first_seen)
```

```kql
let known = _GetWatchlist('KnownDevices') | project Mac = tolower(SearchKey);
DhcpLogs_CL                                   // your DHCP ingestion table
| where Id_s == "10" and IpAddress_s startswith "10.20."
| extend Mac = tolower(MacAddress_s)
| where Mac !in (known)
| summarize FirstSeen = min(TimeGenerated), Ips = make_set(IpAddress_s), Hosts = make_set(HostName_s) by Mac
```

Randomised MAC addresses on phones will show as unknown: enrol corporate phones with a fixed MAC per SSID, or give
BYOD its own SSID and scope. Wireless controllers that log associations are a better source when you have one.

## Triage

1. Disconnect burst: walk the area or check the controller's wIPS for deauth frames; enable 802.11w (PMF).
2. Evil twin: find the client's location, then the rogue AP (controller rogue list, or a survey tool).
3. Unknown device: block the MAC on the controller, then rotate the passphrase — or move to 802.1X so a passphrase is not the only key.
