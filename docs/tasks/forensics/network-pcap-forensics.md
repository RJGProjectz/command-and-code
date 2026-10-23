---
title: Network and PCAP Forensics
type: workflow
platforms: [Linux]
languages: [Bash, Python]
tasks: [Forensics, Investigation, Incident Response]
category: Workflow
security_domain: Network
author: RJGProjectz
date_created: 2026-10-22
last_updated: 2026-10-22
tags: [pcap, pcapng, network-forensics, tcpdump, dumpcap, tshark, capinfos, zeek, zeek-cut, editcap, mergecap, conversations, protocol-hierarchy, dns, http, tls, sni, ja3, file-carving, export-objects, ioc, triage, chain-of-custody, span, tap]
aliases: [pcap forensics, pcap analysis, network forensics, tshark triage, zeek triage, analyze a pcap, read a packet capture, dns exfiltration triage, tls sni extraction, carve files from pcap, network traffic analysis]
difficulty: advanced
verified: false
---

# Network and PCAP Forensics
> **Created**: 2026-10-22T00:00:00Z
> **Last Modified**: 2026-10-22T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands. Before running any script:
> 1. Verify the script integrity and test in a non-production environment.
> 2. Ensure you are in a `Test` or `Dev` environment.
> 3. Validate commands with `--help` / a read-only dry run where supported.
> 4. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The capture and triage commands below follow the documented behaviour of `tcpdump`/`libpcap`,
    the Wireshark/`tshark`/`capinfos` suite and Zeek as cited at the foot of this page, but have
    **not** been lab-run end to end for this page. Capturing production traffic has privacy and
    legal weight, a bad capture filter can **miss the evidence or overwhelm the host**, and carved
    objects are **live attacker artifacts** — work copies, not originals, on an isolated analysis
    box. Confirm each step against your authorization and your own capture before you rely on it.
    Remove this block when `verified: true`.

This is a **read-only triage and analysis** workflow: handle a capture as evidence, carve it down to
what matters, and pull indicators you can pivot on — all defensively. Nothing here generates,
replays or weaponises traffic; it reads packets that were already captured under authorization. For
the live-host side of the same investigation (sockets, process-to-port mapping, resolver state) use
[Network Investigation](../investigation/network-investigation.md); for the discipline and
chain-of-custody principles, see
[Digital Forensics and Incident Response (DFIR)](../../fundamentals/concepts/digital-forensics.md).

---

## 1. Authorization, scope & order of volatility

Packet captures routinely contain personal data, credentials and payloads. Before you capture or
open anything:

| Principle | What it means in practice |
| :--- | :--- |
| **Authorization first** | Capture only traffic you are authorized to — a signed engagement, an IR mandate or your own lab. Full-content capture of user traffic is a legal decision, not a technical one (see [Cyber Law & Authorization](../../fundamentals/concepts/cyber-law.md)). |
| **Preserve the original** | A capture is evidence the moment it exists. Hash it, store the original read-only, and analyse a **copy**. Never carve objects or edit a capture in place. |
| **Order of volatility** | Live traffic is the most volatile source there is — if a host is actively talking to an attacker, start a capture before you reboot, isolate or kill processes. |
| **Minimise footprint** | On a suspect host, capturing adds load and writes files. Prefer a SPAN/TAP off-host where you can; if you must capture on-host, write to external/read-only-exported storage. |

Record what you did (capture point, filter, clock source, operator, time) alongside the file — that
provenance is part of the evidence.

---

## 2. Capture handling (tcpdump / dumpcap, ring buffers, SPAN/TAP)

Where you tap decides what you see. A **network TAP** is a passive, fail-open hardware device that
copies both directions of a link — the forensically cleanest source. A **SPAN/mirror port** on a
switch is easier to get but can drop frames under load and may not mirror errors. On-host capture is
the last resort: it sees only that host and competes with the compromise for resources.

Capture full packets (`-s 0`, the default on modern `tcpdump`) with a tight BPF **capture filter**
so the file stays readable, and rotate into a **ring buffer** so a long capture cannot fill the disk:

```bash
# tcpdump — rotate every 100 MB, keep 10 files (ring buffer), full snaplen, no name resolution.
sudo tcpdump -i eth0 -s 0 -n -w /mnt/evidence/cap_%Y%m%d_%H%M%S.pcap -C 100 -W 10 \
  'not port 22'            # BPF capture filter: exclude your own SSH admin session

# tcpdump — time-based rotation: a new file every 3600 s (-G), timestamped (-w pattern).
sudo tcpdump -i eth0 -s 0 -n -G 3600 -w /mnt/evidence/cap_%Y%m%d_%H%M%S.pcap 'host 10.0.0.50'

# dumpcap (ships with Wireshark) — preferred for long captures; pcapng, ring buffer by size.
sudo dumpcap -i eth0 -b filesize:100000 -b files:10 -w /mnt/evidence/cap.pcapng
```

> `-n` disables DNS/port name resolution so the capture host does **not** generate its own lookups
> (which would pollute the evidence and tip off an attacker). Keep the capture filter narrow but
> never so narrow you clip the thing you are hunting — when unsure, capture broad and filter later
> on analysis (§3+).

Immediately hash and set the original read-only, then work on a copy:

```bash
sha256sum /mnt/evidence/cap.pcapng | tee /mnt/evidence/cap.pcapng.sha256
chmod 0444 /mnt/evidence/cap.pcapng
cp -p /mnt/evidence/cap.pcapng /cases/work/cap.pcapng      # analyse the copy
```

See [Hash Functions](../../fundamentals/concepts/hash-functions.md) for why the hash is the integrity
anchor, and [Compare Files, Folders and Hashes](../administration/compare-files-and-folders.md) to
re-verify later.

---

## 3. First-look triage: `capinfos` and the protocol hierarchy

Before reading packets, read the *shape* of the capture. `capinfos` gives duration, size, packet
count, data rate and SHA-256 in one shot:

```bash
capinfos /cases/work/cap.pcapng
```

`tshark`'s protocol-hierarchy statistic (`-z io,phs`) shows which protocols account for the bytes —
the fastest way to spot "why is 60 % of this capture DNS?" or unexpected plaintext:

```bash
# Protocol hierarchy: bytes/frames per protocol layer.
tshark -r /cases/work/cap.pcapng -q -z io,phs

# Packets-per-second over 60 s buckets — find the burst.
tshark -r /cases/work/cap.pcapng -q -z io,stat,60
```

For very large captures, carve a time window with `editcap` before deeper analysis instead of
re-reading the whole file each time:

```bash
# Keep only the window of interest (UTC); splits are cheap and non-destructive.
editcap -A "2026-10-22 13:00:00" -B "2026-10-22 13:30:00" \
  /cases/work/cap.pcapng /cases/work/window.pcapng

# Merge rotated ring-buffer files back into one timeline.
mergecap -w /cases/work/merged.pcapng /mnt/evidence/cap_*.pcap
```

> Captures over ~20 MB of text output do not belong pasted into a chat or report. Summarise them with
> the local orchestrator (`summarize_files`) or `zeek-cut | sort | uniq -c` roll-ups (§5) and carry
> only the conclusions.

---

## 4. Conversations, endpoints & top talkers

Who is talking to whom, and how much? Conversation and endpoint statistics turn a packet soup into a
ranked list of flows — the backbone of triage:

```bash
# IP conversations: pairs ranked by bytes (add ',tcp' / ',udp' for L4 pairs with ports).
tshark -r /cases/work/cap.pcapng -q -z conv,ip
tshark -r /cases/work/cap.pcapng -q -z conv,tcp

# Endpoints: per-host totals — the top talkers and biggest receivers.
tshark -r /cases/work/cap.pcapng -q -z endpoints,ip
```

Read these for: a single internal host moving far more data **out** than in (possible staging/egress),
long-lived low-volume flows at regular intervals (possible beaconing), and connections to IPs that
never appear in DNS (hard-coded C2). Pivot any suspect external IP to its history on the host and in
telemetry via [Suspicious Outbound Connection](../investigation/suspicious-outbound-connection.md).

---

## 5. Structured logs with Zeek (`zeek -r`)

Zeek turns a capture into structured, greppable logs — one row per connection, DNS query, HTTP
request, TLS handshake and transferred file. For triage it is usually faster than clicking through
packets:

```bash
mkdir -p /cases/work/zeek && cd /cases/work/zeek
zeek -r /cases/work/cap.pcapng       # emits conn.log dns.log http.log ssl.log x509.log files.log weird.log ...
```

`zeek-cut` selects named columns from a log (tab-separated, header-aware):

```bash
# Top connections by responder IP/port and service.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service \
  | sort | uniq -c | sort -rn | head -20

# conn.log 'history' and duration flag long/odd flows (S0 = no response, etc.).
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state duration orig_bytes resp_bytes \
  | sort -k6 -rn | head -20

# weird.log and notice.log are Zeek's own anomaly flags — always skim them.
cat weird.log 2>/dev/null | zeek-cut ts id.orig_h id.resp_h name | head
```

> Zeek logs are the right input for an IOC roll-up (§10) and for the local-model summariser — they are
> compact text, not packets.

---

## 6. DNS extraction & tunneling awareness

DNS is the first place to look for both resolution history and covert channels. Pull every queried
name and rank them:

```bash
# tshark: every DNS query name.
tshark -r /cases/work/cap.pcapng -Y "dns.flags.response == 0" -T fields -e dns.qry.name \
  | sort | uniq -c | sort -rn | head -40

# Zeek equivalent, with query type and answers.
cat /cases/work/zeek/dns.log | zeek-cut query qtype_name answers | sort | uniq -c | sort -rn | head -40
```

Triage signals (awareness, not attribution): a single second-level domain with a very high count of
unique long sub-labels (possible DNS tunneling/exfil), high `TXT`/`NULL` query volume, long base32/hex
labels, and lookups with no corresponding connection. Confirm the behaviour against telemetry with the
[SPL CIM DNS searches](../../detection/spl/network-dns.md) and
[KQL DNS events](../../detection/kql/network-events.md#dns-queries) rather than judging it from one
capture.

---

## 7. HTTP extraction

For plaintext HTTP, pull hosts, URIs and user-agents — the request metadata attackers leak before TLS
hides the rest:

```bash
# tshark: host + URI + method + user-agent for each request.
tshark -r /cases/work/cap.pcapng -Y "http.request" \
  -T fields -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent

# Zeek: the same, already structured, with response status and MIME type.
cat /cases/work/zeek/http.log | zeek-cut host method uri status_code user_agent resp_mime_types \
  | head -40
```

Odd or scripted `User-Agent` strings, requests to raw IPs with a `Host:` that does not resolve, and
fetches of executables/scripts are worth pivoting. Where the capture is of a **web server** under
attack, the payloads in the URIs line up with the detections on
[SPL — Web Attacks](../../detection/spl/web-attacks.md) and
[KQL — Web Attacks](../../detection/kql/web-attacks.md).

---

## 8. TLS / SNI & certificate metadata

Most traffic is encrypted, but the TLS handshake is in the clear. The **SNI** (the server name the
client asks for) and the server certificate tell you *where* a flow is going even when you cannot read
*what*:

```bash
# tshark: SNI from ClientHello (handshake type 1).
tshark -r /cases/work/cap.pcapng -Y "tls.handshake.type == 1" \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn | head -40

# Zeek: SNI + TLS version from ssl.log, subject/issuer from x509.log.
cat /cases/work/zeek/ssl.log  | zeek-cut server_name version cipher | sort | uniq -c | sort -rn | head
cat /cases/work/zeek/x509.log | zeek-cut certificate.subject certificate.issuer | sort | uniq -c | head
```

Watch for: SNI that does not match the destination's DNS history, self-signed or mismatched
certificates, and flows to an IP with **no** SNI at all (raw TLS to hard-coded infrastructure).
Client-fingerprint hashes (**JA3/JA3S**) are a useful pivot when the Zeek JA3 package is loaded — treat
them as an awareness item here; they identify the client/server stack, not the person.

---

## 9. File-carving awareness

You can reconstruct files that crossed the wire. In forensics this is **evidence recovery**, so carve
to an isolated directory, hash everything, and **never execute** what you pull out:

```bash
# tshark: export reconstructed HTTP objects to a directory (also: smb, tftp, imf for email).
mkdir -p /cases/work/objects
tshark -r /cases/work/cap.pcapng --export-objects http,/cases/work/objects

# Zeek: extract transferred files (needs the file-extraction script enabled); then triage by type.
cat /cases/work/zeek/files.log | zeek-cut tx_hosts rx_hosts mime_type filename md5 sha256 | head

# Triage carved objects WITHOUT running them: identify type and hash only.
cd /cases/work/objects
for f in *; do printf '%s\t' "$f"; file -b "$f"; done
sha256sum * > /cases/work/objects.sha256
```

Treat `/cases/work/objects` as untrusted: identify file type with `file`, record hashes, and send the
hashes (not the samples) to threat intel. Deeper static/dynamic malware work belongs on a dedicated,
isolated bench — see [Malware Triage](../incident-response/malware-triage.md) and
[Malware Types and Analysis](../../fundamentals/concepts/malware-types-analysis.md).

---

## 10. IOC extraction & pivoting

The payoff of PCAP triage is a clean indicator list you can pivot on everywhere else. Roll the Zeek
logs up into deduplicated indicators:

```bash
cd /cases/work/zeek
# External IPs contacted.
cat conn.log | zeek-cut id.resp_h | sort -u > /cases/work/ioc_ips.txt
# Domains resolved / SNIs requested.
{ cat dns.log | zeek-cut query; cat ssl.log | zeek-cut server_name; } | sort -u > /cases/work/ioc_domains.txt
# File hashes seen on the wire.
cat files.log | zeek-cut sha256 | sort -u > /cases/work/ioc_hashes.txt
```

Then pivot: check each IP/domain against your host and SIEM history
([Network Investigation](../investigation/network-investigation.md),
[Suspicious Outbound Connection](../investigation/suspicious-outbound-connection.md)), and compare
hashes to known-bad. A small Python de-dupe/normaliser keeps the list consistent across captures:

```python
#!/usr/bin/env python3
# Normalise a column of indicators: strip, lowercase domains, drop blanks/dupes. Read-only, stdin->stdout.
import sys
seen = []
for line in sys.stdin:
    v = line.strip().lower()
    if v and v not in seen:
        seen.append(v)
print("\n".join(seen))
```

```bash
sort -u /cases/work/ioc_domains.txt | python3 normalise_iocs.py > /cases/work/ioc_domains.clean.txt
```

---

## 11. Operational pitfalls

- **Truncated snaplen** — a capture taken with a small `-s` (e.g. legacy 68/96-byte snaplen) clips
  payloads, so `--export-objects`, SNI and HTTP bodies come back empty. Check `capinfos` for the
  snaplen before concluding "nothing was there".
- **Dropped packets** — a SPAN port or an overloaded host silently drops frames; `capinfos` and Zeek's
  `capture_loss.log` report it. Gaps are a data-quality problem, not an absence of evidence.
- **Clock skew** — the capture host's clock, not the suspect's, timestamps packets. Record the capture
  clock source and reconcile against host/log timelines before correlating.
- **Encrypted payloads** — without keys you get metadata only (IPs, SNI, cert, timing, volume). Do not
  assume "encrypted" means "benign"; beaconing and exfil are visible in the flow shape (§4, §8).
- **Analysing the original** — carving or display-filter-saving back onto the evidence file breaks
  integrity. Always work the copy; the read-only original plus its hash is what you present.
- **Huge files** — do not open multi-GB captures in a GUI or paste their dumps; `editcap` a window
  (§3), summarise with Zeek roll-ups, and route big reads to the local model.

---

## Detect it

Capture-time triage finds what already happened; these searches catch the same behaviour continuously
from telemetry:

- **Beaconing / egress to an indicator** → [SPL CIM network/DNS searches](../../detection/spl/network-dns.md) and [KQL network events](../../detection/kql/network-events.md) — the conversation and SNI pivots above map directly onto connection and DNS telemetry.
- **DNS tunneling / exfil** → high-entropy, high-volume lookups per the DNS roll-up (§6), alerted on in [SPL — network & DNS](../../detection/spl/network-dns.md).
- **Web-server attack payloads** → when the capture is server-side HTTP, URIs line up with [SPL — Web Attacks](../../detection/spl/web-attacks.md) · [KQL — Web Attacks](../../detection/kql/web-attacks.md).

---

## Related

- [Network Investigation](../investigation/network-investigation.md) — the live-host counterpart (sockets, process-to-port, resolver state) to this capture-side workflow
- [Suspicious Outbound Connection](../investigation/suspicious-outbound-connection.md) — where to pivot each external IP/domain this triage surfaces
- [Linux Live Response and Forensic Artifact Extraction](linux-live-response-forensics.md) · [Live Memory Acquisition and Volatility Analysis](memory-acquisition-analysis.md) — the host-side evidence that pairs with the wire
- [Malware Triage](../incident-response/malware-triage.md) · [Malware Types and Analysis](../../fundamentals/concepts/malware-types-analysis.md) — where carved objects (§9) go next
- [Digital Forensics and Incident Response (DFIR)](../../fundamentals/concepts/digital-forensics.md) · [Hash Functions](../../fundamentals/concepts/hash-functions.md) — the discipline and integrity anchor
- [Cyber Law & Authorization](../../fundamentals/concepts/cyber-law.md) — why §1 comes first

## External Resources & White Papers

- [tcpdump & libpcap — manual](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark — tshark manual](https://www.wireshark.org/docs/man-pages/tshark.html) · [capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html) · [editcap](https://www.wireshark.org/docs/man-pages/editcap.html) · [mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html)
- [Zeek — documentation](https://docs.zeek.org/) · [zeek-cut](https://docs.zeek.org/en/master/log-formats.html)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [RFC 3227 — Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227)
