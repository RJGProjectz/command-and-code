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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - splunk
  - dns
  - tunneling
  - exfiltration
---

# Splunk Detection — Suspicious DNS Tunneling Signatures

Detects high-frequency base64/encoded subdomain queries directed at a single root apex domain, indicating DNS tunneling C2 or data exfiltration.

## Why it matters

DNS is allowed out of almost every network, so tools such as `iodine`, `dnscat2` and many C2 frameworks hide traffic inside it. The data rides in the subdomain labels (`aGVsbG8gd29ybGQ.c2.example.net`), so tunneling shows up as **many unique, long, random-looking subdomains under one parent domain** from one client.

## Detection Logic

- **Log Source**: DNS Server debug logs or Next-Gen Firewall DNS telemetry
- **ATT&CK Technique**: [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) · exfiltration variant [T1048](https://attack.mitre.org/techniques/T1048/)

```spl
index=network sourcetype=dns message_type=Query
| eval query_length = len(query)
| where query_length > 60
| rex field=query "(?<subdomain>.*)\.(?<apex_domain>[^\.]+\.[^\.]+)$"
| stats count dc(subdomain) as unique_subdomains by src_ip, apex_domain
| where unique_subdomains > 50
| sort - unique_subdomains
```

Volume variant: a client sending far more bytes in queries to one domain than normal, regardless of label length (catches slow tunnels that keep labels short):

```spl
index=network sourcetype=dns message_type=Query earliest=-24h
| rex field=query "(?<apex_domain>[^\.]+\.[^\.]+)$"
| eval qbytes=len(query)
| stats sum(qbytes) as total_bytes dc(query) as unique_queries by src_ip, apex_domain
| where total_bytes > 100000 AND unique_queries > 500
| sort - total_bytes
```

`sourcetype=dns` and `query` / `src_ip` / `message_type` match Splunk Stream. For Zeek use `sourcetype=bro:dns:json` (`query`, `id.orig_h`); for Windows DNS debug logs map the fields in your add-on. The CIM equivalent is the `Network_Resolution` data model (`DNS.query`, `DNS.src`).

## Tuning and false positives

The two-label `apex_domain` regex treats `co.uk` style suffixes as the apex; use the URL Toolbox app's `ut_parse_extended` macro for exact registered domains. Expected noisy sources:

| Source | Example | Action |
| --- | --- | --- |
| Antivirus / EDR cloud lookups | file-reputation queries with hashes in the label | Allowlist the vendor's domain |
| CDNs and cloud services | long generated hostnames | Allowlist by apex domain |
| Email security (DKIM, DNSBL) | `<reversed-ip>.zen.spamhaus.org` | Exclude mail servers as `src_ip` |
| Internal resolvers | every client's queries appear from the forwarder | Log at the client-facing resolver, not upstream |

Keep the allowlist in a lookup (`| lookup dns_tunnel_allowlist apex_domain OUTPUT allowed | where isnull(allowed)`) so it is reviewed, not hidden in the search.

## Respond

1. Look up the apex domain: registration date, hosting, reputation. A domain registered days ago with its own name servers is a strong sign.
2. Decode a few labels (base32/base64/hex) to confirm data is being carried.
3. Find the process on `src_ip` making the queries: Sysmon Event 22 (DNSEvent) or EDR DNS telemetry.
4. Block the domain at the resolver (sinkhole) and investigate the host → [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md).

## Test it

Atomic Red Team [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) has *DNS Large Query Volume* and *DNS Long Domain Query* tests that generate this pattern safely against a domain you choose.

## Related

- [Network and DNS detections (SPL)](network-dns.md)
- [Network Investigation](../../tasks/investigation/network-investigation.md)

## Sources

- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [Splunk CIM — Network Resolution (DNS) data model](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
