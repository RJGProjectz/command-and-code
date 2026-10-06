---
title: Splunk Detection — Security Agent Tampering & EDR Impairment
type: entry
platforms:
  - Windows
  - Linux
  - SentinelOne
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - edr-tampering
  - sentinelone
  - defense-evasion
---

# Splunk Detection — Security Agent Tampering & EDR Impairment

Detects audit events and administrative actions attempting to disable, unload, uninstall, or tamper with endpoint detection and response (EDR) agents.

## Detection Logic

- **Log Source**: EDR Management Audit Logs (`sourcetype="sentinelone:audit"` or Windows Event 7036 / 7040 for stopped security services)
- **ATT&CK Technique**: [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

```spl
index=s1_logs sourcetype="sentinelone:audit"
  (activityType="Agent Uninstalled" OR activityType="Agent Disabled" OR activityType="Anti-Tamper Disabled")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by computerName, user, activityType, src_ip
```

## Endpoint Service Stoppage Query

```spl
index=win_logs source="WinEventLog:System" EventCode=7036
  (param1="*SentinelAgent*" OR param1="*WinDefend*" OR param1="*Sense*")
  param2="stopped"
| table _time, ComputerName, param1, param2
```

## Triage & Response Actions

1. Check for authorized change tickets or scheduled hardware decommissioning.
2. If unauthorized, immediately isolate the endpoint from the network via out-of-band console access or network switch port shutdown.
3. Initiate forensic memory acquisition to identify the tampering executable or kernel driver.
