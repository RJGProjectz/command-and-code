---
title: Splunk Detection — Suspicious DNS Tunneling Signatures
type: entry
platforms:
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
  - dns
  - tunneling
  - exfiltration
---

# Splunk Detection — Suspicious DNS Tunneling Signatures

Detects high-frequency base64/encoded subdomain queries directed at a single root apex domain, indicating DNS tunneling C2 or data exfiltration.

## Detection Logic

- **Log Source**: DNS Server debug logs or Next-Gen Firewall DNS telemetry
- **ATT&CK Technique**: [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

```spl
index=network sourcetype=dns message_type=Query
| eval query_length = len(query)
| where query_length > 60
| rex field=query "(?<subdomain>.*)\.(?<apex_domain>[^\.]+\.[^\.]+)$"
| stats count dc(subdomain) as unique_subdomains by src_ip, apex_domain
| where unique_subdomains > 50
| sort - unique_subdomains
```
