---
title: Splunk Detection — Brute Force Success Correlation
type: entry
platforms:
  - Windows
  - Windows Server
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - brute-force
  - authentication
  - 4625
  - 4624
---

# Splunk Detection — Brute Force Success Correlation

Detects a high-frequency burst of failed logon attempts followed immediately by a successful authentication for the same target user account and source IP within a rolling time window.

## Detection Logic

- **Log Source**: `EventCode=4625` (An account failed to log on) and `EventCode=4624` (An account was successfully logged on)
- **ATT&CK Technique**: [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

```spl
index=win_logs (EventCode=4624 OR EventCode=4625)
| streamstats count(eval(EventCode=4625)) as failure_count window=10 by user, src_ip
| where failure_count >= 5 AND EventCode=4624
| table _time, host, user, src_ip, failure_count, Logon_Type
```

## Field Mappings & Analysis

- `failure_count >= 5`: Threshold for consecutive logon failures before success.
- `src_ip`: Evaluated to confirm authentication attempts originate from the identical pivot IP.
- `Logon_Type`: Identifies interactive (Type 2), network (Type 3), or remote interactive / RDP (Type 10).

## False Positive Tuning

- **User Password Fatigue**: End user incorrectly entering a complex password multiple times before succeeding.
- **Service Account Rotations**: Scheduled tasks or services running with cached old credentials prior to administrative password update.
