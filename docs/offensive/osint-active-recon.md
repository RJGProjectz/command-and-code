---
title: Map an Organization's Attack Surface with OSINT and Active Reconnaissance
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Application
author: RJGProjectz
date_created: 2026-10-23
last_updated: 2026-10-23
tags: [osint, reconnaissance, recon, subdomain-enumeration, subdomain-brute-force, amass, subfinder, dnsx, puredns, theharvester, email-harvesting, people-osint, document-metadata, exiftool, metagoofil, dns-zone-transfer, virtual-host-discovery, google-dorking, attack-surface, parrot-os, kali]
aliases: [osint workflow, active recon, reconnaissance workflow, enumerate subdomains, subdomain brute force, amass subfinder, harvest emails theharvester, people osint, employee enumeration, document metadata osint, exiftool metagoofil, dns zone transfer, axfr, virtual host discovery, map attack surface, footprinting]
difficulty: intermediate
verified: false
---

# Map an Organization's Attack Surface with OSINT and Active Reconnaissance
> **Created**: 2026-10-23T00:00:00Z
> **Last Modified**: 2026-10-23T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Reconnaissance is where an engagement starts and where scope is easiest to break.
> 1. Enumerate **only** domains, hosts and people inside a signed engagement, an in-scope bug-bounty
>    asset, or your own lab. Subdomains and acquisitions resolve to assets you may **not** be authorized
>    to touch — confirm each against the scope before any active probe.
> 2. **Passive first.** Everything in §1–§2 queries third parties, not the target. Active steps (§3
>    brute force, §5 zone transfer / vhost probing) send traffic to the target or its DNS — run them only
>    when the scope allows direct contact, inside the agreed rate and time window, and keep a log.
> 3. People OSINT (§4) handles **personal data**. Collect only what the engagement needs (corporate
>    emails, name/role to model phishing surface), store it with the rest of the evidence, and never use
>    it to target individuals outside the authorization — see [Cyber Law](../fundamentals/concepts/cyber-law.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (Parrot OS / Kali packages) but have not
    been lab-run for this page. Confirm flags against each tool's `--help`/man page in your build.
    Remove this block when `verified: true`.

**Trigger:** an authorized engagement has begun and you have a root domain or an organization name, and
need to turn that single seed into the full map of **what the target exposes to the internet** — every
subdomain, host, email address and public document that an attacker would find first. Reconnaissance
decides everything downstream: you cannot assess what you have not discovered.

**Goal:** build an evidenced inventory of the target's external footprint — domains and subdomains,
resolved hosts and live services, people and email addresses, and leaked document metadata — moving
**passive → active** so the quiet, zero-touch sources are exhausted before any packet reaches the
target. This page is Stage 1 (Reconnaissance) of the
[red-team lifecycle](index.md); it hands its resolved, live hosts to the active workflows:
[Web Application Assessment](web-application-assessment.md),
[Web API Assessment](web-api-assessment.md), and
[Network & Infrastructure Enumeration](network-infrastructure-enumeration.md). For the theory, see
[OSINT & Reconnaissance](../fundamentals/concepts/osint.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Passive footprint | [`FUNC_BASH_GET_WEB_OSINT.sh`](passive-web-osint.md), `amass -passive`, `subfinder` | Subdomains, DNS, registration — target sees nothing |
| Subdomain brute (active) | `puredns`/`gobuster dns`, `dnsx` | Unlisted hosts; which resolve |
| Live host triage | `httpx` | Which hosts answer HTTP(S), titles, tech |
| People & email | `theHarvester`, `crosslinked` | Addresses, name→email format, phishing surface |
| Document metadata | `metagoofil`/`pymeta`, `exiftool` | Usernames, software, internal paths from public files |
| Active DNS recon | `dig AXFR`, `dnsrecon`, vhost `ffuf` | Zone transfers, PTRs, virtual hosts behind one IP |

## 0. Set the scope once

```bash
DOMAIN="REPLACE-with-authorized-domain.example"   # the in-scope root
ORG="REPLACE Org Name"                             # for people/doc OSINT
OUT="./recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
# Keep the authorized-scope list beside the evidence; check every discovered host against it.
printf '%s\n' "$DOMAIN" > "$OUT/in_scope.txt"
```

## 1. Passive footprint first (zero-touch)

Start with sources that never touch the target. The companion tool
[`FUNC_BASH_GET_WEB_OSINT.sh`](passive-web-osint.md) already rolls up DNS, WHOIS/RDAP, Certificate
Transparency, Wayback and Shodan InternetDB into NDJSON — run it first, then widen with the
purpose-built passive subdomain engines:

```bash
# Tool: DNS + WHOIS/RDAP + CT + Wayback + Shodan, machine-readable
./scripts/bash/FUNC_BASH_GET_WEB_OSINT.sh "$DOMAIN" -o "$OUT/passive" --format both

# amass in PASSIVE mode — aggregates CT, scrapers and APIs, no DNS brute, no target contact
amass enum -passive -d "$DOMAIN" -o "$OUT/amass_passive.txt"

# subfinder — fast passive subdomain discovery across many sources
subfinder -d "$DOMAIN" -all -silent -o "$OUT/subfinder.txt"
```

Merge every passive source into one candidate list — this is the input to resolution and brute force:

```bash
cat "$OUT/passive/$DOMAIN/subdomains.txt" "$OUT/amass_passive.txt" "$OUT/subfinder.txt" 2>/dev/null \
  | tr 'A-Z' 'a-z' | sort -u > "$OUT/subs_passive.txt"
wc -l < "$OUT/subs_passive.txt"
```

## 2. Resolve what you found

Discovery is not existence — resolve the candidates to see which are live and where they point.
`dnsx` validates and annotates in one pass:

```bash
# Keep only names that resolve; capture the A records and any CNAME chains
dnsx -l "$OUT/subs_passive.txt" -a -resp -silent -o "$OUT/resolved_passive.txt"
# Extract unique IPs for the network-enumeration hand-off
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUT/resolved_passive.txt" | sort -u > "$OUT/ips.txt"
```

A CNAME pointing at a decommissioned cloud/SaaS bucket is a **subdomain-takeover** candidate — record
it as a finding (do not claim the resource); confirm later against the provider's documented takeover
signatures.

## 3. Active subdomain brute force *(scope must allow target DNS contact)*

Passive sources miss hosts that were never logged publicly. Brute force fills the gap by querying the
target's DNS directly — this **touches the target's resolvers**, so only run it when the scope permits.

```bash
# puredns brute-forces and resolves against a vetted resolver list, filtering wildcards
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt "$DOMAIN" \
  -r "$OUT/resolvers.txt" -w "$OUT/subs_brute.txt"

# Or gobuster's DNS mode if puredns/massdns is not installed
gobuster dns -d "$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -o "$OUT/gobuster_dns.txt"
```

Watch for **wildcard DNS** (every random name resolves) — `puredns` filters it; with `gobuster` add a
random-prefix sanity check first. Fold the brute-forced names back through §2's `dnsx` step so the
final list is resolution-verified.

## 4. Live host triage

Turn resolved names into a short list of things that actually serve content. `httpx` probes HTTP/HTTPS
and records status, title and detected technology in one sweep — a small, bounded amount of direct
contact that scopes the rest of the engagement:

```bash
sort -u "$OUT/subs_passive.txt" "$OUT/subs_brute.txt" 2>/dev/null > "$OUT/subs_all.txt"
httpx -l "$OUT/subs_all.txt" -silent -status-code -title -tech-detect -web-server \
  -o "$OUT/live_hosts.txt"
```

Each live host is an entry point: hand web hosts to [Web Application Assessment](web-application-assessment.md),
API hosts to [Web API Assessment](web-api-assessment.md), and the IPs in `ips.txt` to
[Network & Infrastructure Enumeration](network-infrastructure-enumeration.md).

## 5. People, email and document OSINT

The human attack surface is part of the map. Harvest **corporate** addresses and the organization's
email-naming convention (the input to an authorized phishing-surface assessment), and pull metadata
from public documents — all still enumeration, never contact with the people themselves.

```bash
# theHarvester: emails, hosts and names from search engines, CT and public sources
theHarvester -d "$DOMAIN" -b bing,crtsh,duckduckgo,hackertarget -f "$OUT/theharvester"

# Derive the email format (e.g. first.last@) from scraped employee names, without contacting anyone
crosslinked -f '{first}.{last}@'"$DOMAIN" -t "$ORG" -o "$OUT/email_candidates.txt"
```

Public documents (PDF, DOCX, XLSX) routinely leak internal usernames, software versions and file
paths. `metagoofil`/`pymeta` find and fetch them from search engines; `exiftool` reads the metadata:

```bash
# Discover and download indexed documents for the domain
pymeta -d "$DOMAIN" -f "$OUT/docs_meta.csv"       # or: metagoofil -d "$DOMAIN" -t pdf,docx,xlsx -o "$OUT/docs"

# Pull Author / Creator / Producer / software and any embedded paths from what you fetched
exiftool -Author -Creator -Producer -Software -r "$OUT/docs" 2>/dev/null | tee "$OUT/doc_metadata.txt"
```

Google dorking (`site:$DOMAIN filetype:pdf`, `site:$DOMAIN inurl:admin`,
`intitle:"index of"`) complements this manually — it is a search of a third party's index, so keep it
to reading results. Treat harvested emails and names as personal data under the §0 CAUTION.

## 6. Consolidate and hand off

Fold every source into one evidenced inventory so a finding traces back to what produced it, then pass
the live hosts into the active workflows:

```bash
{
  echo "# Recon inventory for $DOMAIN  ($(date -u +%FT%TZ))"
  echo "## Live hosts";        cat "$OUT/live_hosts.txt"
  echo "## Resolved IPs";      cat "$OUT/ips.txt"
  echo "## Emails (corporate)"; grep -hoE "[a-z0-9._%+-]+@$DOMAIN" "$OUT"/theharvester* 2>/dev/null | sort -u
} > "$OUT/inventory.md"
```

Keep the raw per-tool output under `"$OUT"` as evidence. This feeds the reporting phase in
[Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md); the shared
enumeration-findings → NDJSON normaliser (planned, WP-87) will give every recon tool here one schema.

## Detect it

Active reconnaissance is **noisy and visible** — the same steps drive detection content on the
[Detection](../detection/index.md) tab. Pair each technique with what catches it:

| Offensive technique here | Detect it with |
| :--- | :--- |
| Subdomain brute force / DNS flood against the target's resolvers (§3) | [SPL — Network and DNS Hunting](../detection/spl/network-dns.md) · [KQL — Network Event Hunting](../detection/kql/network-events.md) |
| Zone-transfer (AXFR) and vhost probing (§5) | [SPL — Network and DNS Hunting](../detection/spl/network-dns.md) |
| Live-host sweeps (`httpx`) hitting many vhosts fast (§4) | [SPL — Web Attacks](../detection/spl/web-attacks.md) · [KQL — Web Attacks](../detection/kql/web-attacks.md) |

Passive OSINT (§1–§2) is, by design, **not** visible to the target — which is exactly why defenders
must reduce their public footprint rather than hope to alarm on it.

## Notes

- **Passive before active, always.** §1–§2 cost the target nothing and often find most of the surface.
  Only cross into §3/§5 when the scope authorizes direct contact, and log it.
- **Discovery ≠ scope.** A subdomain you found may be a third party's asset (shared SaaS, a partner).
  Resolve it, then confirm against `in_scope.txt` before any active probe — this is the single easiest
  way to break scope.
- **Dangling CNAMEs are findings, not conquests.** Record subdomain-takeover candidates; do not claim
  the orphaned resource.
- **Personal data discipline.** Collect only the emails/names the engagement needs, store them with the
  evidence, and never act against individuals outside the authorization.
- Install notes: `amass`, `theHarvester`, `dnsrecon`, `exiftool`, `ffuf` ship on or `apt install` onto
  Parrot/Kali; `subfinder`, `dnsx`, `httpx` (ProjectDiscovery), `puredns`, `crosslinked`, `pymeta` and
  `metagoofil` are separate installs.

## Related

- [Offensive — Overview](index.md) — this is Stage 1 (Reconnaissance)
- [Passive Web OSINT Tool](passive-web-osint.md) — the zero-touch data-source engine §1 runs
- [Web Application Assessment](web-application-assessment.md) · [Web API Assessment](web-api-assessment.md) — where the live web/API hosts go
- [Network & Infrastructure Enumeration](network-infrastructure-enumeration.md) — where the resolved IPs go
- [Cloud Attack Surface Enumeration](cloud-attack-surface-enumeration.md) — public cloud exposure for the same org
- Reference: [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md) · [Social Engineering](../fundamentals/concepts/social-engineering.md) · [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md)
- Defensive counterpart: [Email Authentication Deployment (SPF/DKIM/DMARC)](../tasks/administration/email-authentication-deployment.md) — blunts the spoofing that harvested addresses enable

## External Resources & White Papers

- [OWASP Web Security Testing Guide — Information Gathering](https://owasp.org/www-project-web-security-testing-guide/) — the methodology this page follows
- [OWASP Amass](https://github.com/owasp-amass/amass) · [subfinder](https://github.com/projectdiscovery/subfinder) · [dnsx](https://github.com/projectdiscovery/dnsx) · [httpx](https://github.com/projectdiscovery/httpx) · [puredns](https://github.com/d3mondev/puredns)
- [theHarvester](https://github.com/laramies/theHarvester) · [metagoofil](https://github.com/opsdisk/metagoofil) · [ExifTool](https://exiftool.org/)
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database) — curated search dorks
