---
title: Passive Web OSINT Tool (one or many targets)
type: tool
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Tool
security_domain: Application
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-22
tags: [osint, passive-recon, reconnaissance, dns, whois, rdap, certificate-transparency, crt-sh, wayback, shodan, internetdb, subdomains, ndjson, bulk, web-enumeration]
aliases: [passive web osint, passive recon script, enumerate website passively, bulk domain recon, crt.sh subdomains, wayback urls, shodan internetdb, dns whois recon tool, many targets osint, FUNC_BASH_GET_WEB_OSINT]
difficulty: intermediate
verified: false
---

# Passive Web OSINT Tool (one or many targets)
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-22T02:15:52Z
> **Author**: RJGProjectz

> [!NOTE]
> **Passive by default.** `scripts/bash/FUNC_BASH_GET_WEB_OSINT.sh` sends no traffic to the target
> host — no homepage GET, no `robots.txt` fetch, no port scan. Every lookup queries a third-party or
> public data source, so the target sees nothing. The opt-in `--fingerprint` flag adds **one** direct
> GET per target to infer the web stack (server, language, framework, CMS); it touches the target and
> leaves the passive path, so it is off unless you ask for it. For a full **active** workflow (nmap,
> whatweb, nuclei) use [Web Application Assessment](web-application-assessment.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The script is written against the documented behaviour of its tools and public APIs and is
    syntax-checked, but has not been lab-run end to end for this page (it needs `jq`/`dig`, absent on
    the authoring host). Confirm it on your Kali/Parrot build before relying on the output. Remove this
    block when `verified: true`.

> [!CAUTION]
> **Authorized use only.** Passive reconnaissance can still be restricted by law and by engagement
> scope, and each data provider (crt.sh, the Wayback Machine, Shodan, RDAP) has its own terms and rate
> limits. Only enumerate targets you own or are authorized to assess — see
> [Cyber Law](../fundamentals/concepts/cyber-law.md).

**What it does:** given one domain or a file of many, it gathers everything learnable **without
touching the target** and writes both a human summary and machine-readable NDJSON.

| Source | What it returns | Why it is passive |
| :--- | :--- | :--- |
| DNS (`dig` via a public resolver) | A/AAAA/MX/NS/TXT/SOA/CAA records | Queries a resolver, not the target |
| WHOIS / RDAP (`rdap.org`, `whois`) | Registrar, registration/expiry dates, nameservers, status | Registry data, not the target |
| Certificate Transparency ([crt.sh](https://crt.sh/)) | Subdomains and certificate history | Public CT logs |
| Wayback Machine (CDX API) | Historical URLs and paths ever archived | Archive.org's cache |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Open ports, CPEs, and known CVEs per resolved IP | Shodan's own scan data, keyless |

## Usage

```bash
# One target — summary to the terminal, evidence + NDJSON under ./webosint_<timestamp>/
./scripts/bash/FUNC_BASH_GET_WEB_OSINT.sh example.com

# Many targets from a file (one per line; '#' comments ignored), custom output dir, both outputs
./scripts/bash/FUNC_BASH_GET_WEB_OSINT.sh -f targets.txt -o ./recon --format both

# Trim the noisy/slow sources, pin a resolver
./scripts/bash/FUNC_BASH_GET_WEB_OSINT.sh example.com --no-wayback --resolver 9.9.9.9

# Add ACTIVE stack fingerprinting (one direct GET per target — leaves the passive path)
./scripts/bash/FUNC_BASH_GET_WEB_OSINT.sh example.com --fingerprint
```

| Flag | Effect |
| :--- | :--- |
| `-f, --file FILE` | Read targets from a file (one per line) |
| `-o, --out DIR` | Evidence + reports directory (default `./webosint_<date>`) |
| `--format text\|json\|both` | stdout format; NDJSON is always written to `results.ndjson` |
| `--resolver IP` | Public DNS resolver to use (default `1.1.1.1`) |
| `--no-ct` / `--no-wayback` / `--no-shodan` / `--no-whois` | Skip a source |
| `--fingerprint` (alias `--active`) | **ACTIVE** — one direct GET per target to fingerprint the web stack (server/language/framework/CMS). Off by default; touches the target |
| `-h, --help` | Usage |

## Output

Per target, under the output directory:

```text
webosint_<date>/
├── results.ndjson                 # one JSON record per target (the machine output)
└── example.com/
    ├── ips.txt
    ├── dns_A.txt … dns_CAA.txt
    ├── rdap.json  (or whois.txt)
    ├── subdomains.txt             # from Certificate Transparency
    ├── wayback_urls.txt
    ├── shodan_internetdb.ndjson
    ├── fp_headers.txt             # only with --fingerprint (response headers)
    └── fp_body.html               # only with --fingerprint (homepage HTML)
```

Each `results.ndjson` record has a stable schema:

```json
{
  "domain": "example.com",
  "scanned": "2026-10-21T00:00:00-06:00",
  "ips": ["93.184.216.34"],
  "dns": { "A": [], "MX": [], "NS": [], "TXT": [], "SOA": [], "CAA": [] },
  "registration": { "registrar": null, "events": [], "nameservers": [] },
  "subdomain_count": 0,
  "wayback_count": 0,
  "shodan": [],
  "fingerprint": {}
}
```

With `--fingerprint`, the `fingerprint` object is populated from the single direct request, e.g.:

```json
{
  "fingerprint": {
    "url": "https://example.com/",
    "http_code": "200",
    "server": "Apache/2.4.57",
    "powered_by": "PHP/8.2.12",
    "technology": ["server: Apache/2.4.57", "x-powered-by: PHP/8.2.12", "WordPress"]
  }
}
```

Feed `results.ndjson` straight into `jq` for triage — e.g. every host that Shodan already shows a CVE
for:

```bash
jq -r 'select((.shodan[]?.vulns // []) | length > 0) | .domain' recon/results.ndjson
```

## Requirements

`curl` and `jq` are required; `dig` (dnsutils/bind) and `whois` are strongly recommended — all ship on
Kali/Parrot (`sudo apt install jq dnsutils whois`). Without `dig`, the DNS section and IP resolution
(and therefore the Shodan lookup) are skipped; without `whois`, registration data comes from RDAP over
HTTP.

## Notes

- **Passive by default; active is explicit.** No source touches the target unless you pass
  `--fingerprint`, which is the one step that does (a single GET per target). Everything else stays
  third-party. For deeper, noisier live fingerprinting (nmap/whatweb/nuclei) use the active workflow.
- **`--fingerprint` is in-scope-gated by you.** It leaves the passive path and will appear in the
  target's logs, so only enable it against hosts you are authorized to probe directly.
- **Rate and terms.** Bulk runs hit crt.sh / archive.org / Shodan repeatedly; keep target lists
  reasonable and respect each provider's limits. The per-request timeout is capped and failures degrade
  to empty rather than aborting the run.
- **Evidence first.** Raw per-source files are kept so a finding can be traced back to exactly what the
  source returned, which matters for reporting.

## Related

- [Offensive — Overview](index.md)
- [Web Application Assessment](web-application-assessment.md) — the **active** counterpart
- [Cloud Attack Surface Enumeration](cloud-attack-surface-enumeration.md) — public cloud exposure
- Reference: [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md)

## External Resources & White Papers

- [crt.sh — Certificate Transparency search](https://crt.sh/)
- [Wayback Machine CDX Server API](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [Shodan InternetDB](https://internetdb.shodan.io/) — keyless host data
- [RDAP (RFC 7483)](https://datatracker.ietf.org/doc/html/rfc7483) — structured registration data
