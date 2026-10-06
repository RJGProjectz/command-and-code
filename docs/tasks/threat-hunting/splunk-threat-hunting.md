---
title: Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk
type: workflow
platforms:
  - Splunk
  - Windows
  - Linux
languages:
  - SPL
tasks:
  - Threat Hunting
  - Detection Engineering
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - splunk
  - threat-hunting
  - beaconing
  - tstats
  - lolbins
---

# Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk

Systematic threat hunting methodologies utilizing accelerated Splunk data models (`tstats`) and statistical anomalies to uncover advanced persistent threats (APTs) bypassing signature alerts.

## 1. Hypothesis: C2 Beaconing via Regularity Analysis

Adversaries communicate with command and control infrastructure at automated intervals with small amounts of randomized delay (jitter).

```spl
index=network sourcetype=firewall direction=outbound dest_port=443
| sort 0 src_ip, dest_ip, _time
| streamstats current=f window=1 last(_time) as prev_time by src_ip, dest_ip
| eval delta = _time - prev_time
| stats count, avg(delta) as avg_interval, stdev(delta) as jitter by src_ip, dest_ip
| where count > 50 AND jitter < 5
| sort - count
```

- **Low Jitter ($< 5\text{s}$)**: Indicates automated programmatic connection cycles rather than human web browsing.

## 2. Hypothesis: Defense Evasion via Renamed System Binaries

Adversaries rename native binaries (e.g. `cmd.exe` renamed to `svchost.exe`) to blend into process lists.

```spl
| tstats count from datamodel=Endpoint.Processes where Processes.process_name!=Processes.original_file_name by Processes.host, Processes.process_name, Processes.original_file_name, Processes.process_path
```

## 3. Hypothesis: Fleet Log Pipeline Blindspots (Missing Forwarders)

Hunt for hosts that have stopped generating security telemetry over the last 24 hours:

```spl
| tstats latest(_time) as last_seen where index=endpoint by host
| eval hours_offline = round((now() - last_seen)/3600, 2)
| where hours_offline > 24
| sort - hours_offline
```
