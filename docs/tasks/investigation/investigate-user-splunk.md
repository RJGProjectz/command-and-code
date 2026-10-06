---
title: Investigation Workflow — Compromised User Identity Triage in Splunk
type: workflow
platforms:
  - Splunk
  - Windows
  - Entra ID
languages:
  - SPL
tasks:
  - Investigation
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - user-investigation
  - identity
  - impossible-travel
  - lateral-movement
---

# Investigation Workflow — Compromised User Identity Triage in Splunk

SOC triage procedure for analyzing anomalous user activity, suspected credential stuffing, insider threats, and lateral movement.

## 1. Authentication Velocity & Failure-to-Success Ratio

```spl
index=win_logs user="<TARGET_USER>" (EventCode=4624 OR EventCode=4625)
| timechart span=15m count(eval(EventCode=4625)) as Failures, count(eval(EventCode=4624)) as Successes
```

## 2. Impossible Travel & Geolocation Anomalies

Analyze cloud sign-in attempts from disparate geographical locations within a 1-hour window:

```spl
index=azure sourcetype="azure:signin" user="<TARGET_USER>"
| iplocation src_ip
| stats dc(Country) as country_count values(Country) as countries values(City) as cities by user, _time span=1h
| where country_count > 1
```

## 3. Lateral Movement Host Count

Identify all destination hosts accessed by this identity over the last 24 hours:

```spl
index=win_logs EventCode=4624 user="<TARGET_USER>" Logon_Type=3
| stats dc(ComputerName) as host_count values(ComputerName) as targets by user, src_ip
| where host_count > 3
```

- **Assessment**: Legitimate standard users rarely authenticate to more than 2 distinct network workstations concurrently.
