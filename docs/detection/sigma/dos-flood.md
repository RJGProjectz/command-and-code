---
title: Detection Rule — Network Flood (DoS / DDoS)
type: entry
platforms:
  - Azure
  - Splunk
languages:
  - Sigma
  - KQL
  - SPL
tasks:
  - Detection Engineering
  - Incident Response
verified: true
last_verified: 2026-10-13
difficulty: intermediate
tags:
  - dos
  - ddos
  - flood
  - firewall
  - netflow
  - t1498
---

# Detection Rule — Network Flood (DoS / DDoS)

Detects a volumetric flood against one destination: a jump in connections per minute, often from many sources
(DDoS) or one source at very high rate (DoS). Firewall or flow logs are the source; endpoints usually fall over
before they log anything useful.

!!! warning "Before you deploy"
    Checked (2026-10-13) against the Sigma correlation specification, the SigmaHQ firewall field names, Microsoft
    Learn (`CommonSecurityLog`, Azure DDoS Protection logs) and the Splunk CIM; not run against live traffic.
    Thresholds are placeholders. Baseline your busiest public service first and set the threshold well above its
    normal peak. Field names follow CEF (`CommonSecurityLog`) and the Splunk CIM `Network_Traffic` data model.

- **ATT&CK**: [T1498 — Network Denial of Service](https://attack.mitre.org/techniques/T1498/), [T1499 — Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- **Concept**: [Denial of Service](../../fundamentals/concepts/denial-of-service.md)

## Sigma rule (correlation)

Uses the Sigma v2 correlation format: a base rule for firewall connections and an `event_count` correlation on it.

```yaml
title: Firewall Connection to Public Service
id: c82f9a7f-a026-4a72-9a17-ab060929673a
name: firewall_inbound_connection
status: experimental
description: Base rule - inbound connections logged by the perimeter firewall.
author: RJGProjectz
date: 2026-10-11
logsource:
  category: firewall
detection:
  selection:
    action:     # vendors log different words; list the ones your firewall uses
      - allow
      - allowed
      - accept
      - deny
      - denied
      - drop
      - blocked
  condition: selection
level: informational
---
title: Possible Network Flood Against a Single Destination
id: cd3d99b4-0ed9-4b7d-9ef6-acbebf283a08
status: experimental
description: More than 20000 firewall events to one destination IP and port in one minute.
references:
  - https://attack.mitre.org/techniques/T1498/
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.impact
  - attack.t1498
correlation:
  type: event_count
  rules:
    - firewall_inbound_connection
  group-by:
    - dst_ip
    - dst_port
  timespan: 1m
  condition:
    gte: 20000
falsepositives:
  - Marketing launches, product releases, load tests
  - Vulnerability scanners and uptime monitors with aggressive schedules
level: high
```

## KQL (Microsoft Sentinel)

Baseline-relative: flags a minute that is 10x the destination's 7-day 99th percentile **and** above a floor.

```kql
let lookback = 7d;
let floor = 5000;
let baseline = CommonSecurityLog
    | where TimeGenerated between (ago(lookback) .. ago(1h))
    | summarize PerMin = count() by DestinationIP, DestinationPort, bin(TimeGenerated, 1m)
    | summarize P99 = percentile(PerMin, 99) by DestinationIP, DestinationPort;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| summarize Events = count(), Sources = dcount(SourceIP) by DestinationIP, DestinationPort, bin(TimeGenerated, 1m)
| join kind=leftouter baseline on DestinationIP, DestinationPort
| where Events > floor and Events > 10 * coalesce(P99, 0)
| extend Shape = iff(Sources > 100, "distributed", "single/few sources")
| project TimeGenerated, DestinationIP, DestinationPort, Events, Sources, P99, Shape
```

If the target sits behind Azure DDoS Protection, its own notifications are a better signal:

```kql
AzureDiagnostics
| where Category == "DDoSProtectionNotifications"
| project TimeGenerated, Resource, type_s, Message
```

`type_s` is the notification type (`MitigationStarted`, `MitigationStopped`); `DDoSMitigationReports` holds the
attack vectors and top sources once mitigation starts.

## SPL

```spl
| tstats count dc(All_Traffic.src) as sources from datamodel=Network_Traffic
    where nodename=All_Traffic by All_Traffic.dest, All_Traffic.dest_port, _time span=1m
| rename All_Traffic.* as *
| eventstats avg(count) as avg_count stdev(count) as sd_count by dest, dest_port
| where count > 5000 AND count > avg_count + 5*sd_count
| eval shape=if(sources > 100, "distributed", "single/few sources")
| sort - count
```

## Triage

1. Is the service actually degraded? Check health probes and response times before escalating.
2. `single/few sources` — block or rate-limit at the edge. `distributed` — engage the upstream provider / DDoS service.
3. Follow [Network Investigation](../../tasks/investigation/network-investigation.md) for the top talkers and protocol mix (SYN, UDP, HTTP).

## Test it

Atomic Red Team has no test for [T1498](https://attack.mitre.org/techniques/T1498/) or
[T1499](https://attack.mitre.org/techniques/T1499/): flooding is not safe to automate. Test the pipeline instead:
copy the rule with the threshold lowered to 100, then send 200 requests from one lab host to a lab web server you own.

```bash
for i in $(seq 1 200); do curl -s -o /dev/null "http://<LAB_WEB_SERVER>/"; done
```

For Azure resources, Microsoft supports real attack simulations only through its approved simulation partners.

## Sources

- [Sigma correlation rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
- [Microsoft Learn — View Azure DDoS Protection logs](https://learn.microsoft.com/azure/ddos-protection/ddos-view-diagnostic-logs)
- [Microsoft Learn — Test with simulation partners](https://learn.microsoft.com/azure/ddos-protection/test-through-simulations)
- [Splunk CIM — Network Traffic data model](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
