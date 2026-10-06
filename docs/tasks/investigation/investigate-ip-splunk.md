---
title: Investigation Workflow — Suspicious IP Address Analysis in Splunk
type: workflow
platforms:
  - Splunk
  - Windows
  - Linux
languages:
  - SPL
tasks:
  - Investigation
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - investigation
  - ip-analysis
  - firewall
  - exfiltration
---

# Investigation Workflow — Suspicious IP Address Analysis in Splunk

End-to-end triage procedure for analyzing an external or internal IP address flagged by security alerts, threat intel feeds, or anomalous traffic spikes.

## 1. Outbound Traffic Volume & Potential Exfiltration

Assess total data transferred from internal hosts to the target destination IP:

```spl
index=network sourcetype=firewall direction=outbound dest_ip="<TARGET_IP>"
| stats sum(bytes) as total_bytes by src_ip, dest_ip, transport
| eval total_mb = round(total_bytes/1024/1024, 2)
| sort - total_mb
```

- **Threshold**: Outbound transfers exceeding 100 MB to unclassified external endpoints warrant immediate application payload review.

## 2. Inbound Connection Frequency & Scanning

Determine if the IP is probing external perimeters:

```spl
index=network sourcetype=firewall direction=inbound src_ip="<TARGET_IP>"
| bucket _time span=5m
| stats count as hits, dc(dest_port) as scanned_ports by src_ip, _time
| where hits > 50 OR scanned_ports > 10
```

## 3. Rarity & Baseline Frequency

Calculate whether connections to this destination are unique across the fleet:

```spl
index=network sourcetype=firewall direction=outbound
| stats dc(src_ip) as distinct_sources by dest_ip
| where distinct_sources == 1 AND dest_ip="<TARGET_IP>"
```

- **Signal**: A destination contacted by only 1 host in the enterprise has a high probability of being dedicated C2 infrastructure.

## 4. Threat Intelligence Cross-Correlation

```spl
index=threat_activity (src_ip="<TARGET_IP>" OR dest_ip="<TARGET_IP>")
| stats count by threat_key, description, confidence
```
