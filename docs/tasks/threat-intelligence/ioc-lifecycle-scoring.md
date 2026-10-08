---
title: Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring
type: workflow
platforms:
  - Windows
  - Linux
  - Microsoft Defender
  - Splunk
languages:
  - Python
  - PowerShell
  - Bash
  - KQL
  - SPL
tasks:
  - Threat Intelligence
  - Detection Engineering
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - threat-intelligence
  - ioc-lifecycle
  - confidence-scoring
  - pyramid-of-pain
  - indicator-aging
  - defanging
---

# Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring

Indicators of Compromise (IoCs) form the tactical baseline of threat detection. However, unmanaged indicator ingestion causes alert fatigue, false positives, and degraded SIEM query performance. This guide establishes a rigorous operational lifecycle for indicator extraction, defanging, confidence scoring, and automated time-decay pruning.

---

## 1. The Pyramid of Pain & Operational Value

David Bianco's **Pyramid of Pain** defines the relative difficulty and cost inflicted upon adversaries when defenders detect and deny specific indicator tiers:

```
            ▲
           / \     TTPs (Tactics, Techniques, Procedures) ── High Defender Value / Extreme Adversary Cost
          /   \
         /     \   Tools (Mimikatz, Cobalt Strike, Impacket)
        /       \
       /         \ Network / Host Artifacts (User-Agent, Mutex, Registry Key)
      /           \
     /             \ Domain Names (Dynamic DNS, Phishing Domains)
    /               \
   /                 \ IP Addresses (Fast-Flux C2, Tor Exit Nodes)
  /                   \
 /─────────────────────\ Hash Values (MD5, SHA1, SHA256) ── Trivial Adversary Cost (Polymorphic Payloads)
```

| Indicator Level | Defense Utility | Lifespan / Volatility | False Positive Risk | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **Hash (SHA256)** | High certainty for known samples | Months to years | Very Low | Automated EDR block / Quarantine |
| **IP Address** | High timeliness, ephemeral | 3 to 14 days | Medium to High (Shared Cloud / CDN) | Alert & Threat Hunt (Do not block indefinitely) |
| **Domain Name** | Medium timeliness | 14 to 60 days | Low to Medium | Sinkhole / DNS block |
| **Tool / TTP** | Highest strategic resilience | Indefinite | Low | Behavioral Detection Rules (Sigma/KQL) |

---

## 2. Dynamic Confidence Scoring & Decay Formula

Rather than treating all threat feed indicators equally, assign a dynamic **Confidence Score ($S_t$)** that decays over time:

$$S(t) = \left( R_{\text{source}} \times (1 + \ln(C)) \right) \cdot e^{-\lambda t} - P_{\text{FP}}$$

* $R_{\text{source}}$: Source Reputation Base Score ($0$ to $100$).
* $C$: Corroboration Count (number of independent intelligence feeds reporting the indicator).
* $\lambda$: Decay constant ($\lambda = \frac{\ln(2)}{t_{1/2}}$, where $t_{1/2}$ is the indicator half-life).
* $t$: Days elapsed since indicator was last sighted.
* $P_{\text{FP}}$: False positive penalty ($50$ points if benign traffic was previously observed).

### Indicator Half-Life ($t_{1/2}$) Matrix

| Observable Type | Half-Life ($t_{1/2}$) | Maximum Retention | Inline Action Threshold |
| :--- | :---: | :---: | :---: |
| **IPv4 Address** | 7 Days | 21 Days | Score $\ge 80$ |
| **Domain Name** | 15 Days | 45 Days | Score $\ge 75$ |
| **SHA256 Hash** | 90 Days | 365 Days | Score $\ge 60$ |

---

## 3. Automated IoC Extraction & Defanging Engine

This standard-library Python utility ingests raw incident notes or CTI threat reports, extracts candidate observables, strips private/reserved network ranges, and calculates dynamic confidence scores:

```python
#!/usr/bin/env python3
"""
tools/extract_iocs.py — Standard-library IoC extraction, defanging, and scoring tool.
"""
import re
import sys
import ipaddress
from datetime import datetime, timezone

# Regex patterns for observables
RE_IPV4 = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
RE_DEFANGED_IP = r"\b(?:[0-9]{1,3}\[\.\]){3}[0-9]{1,3}\b"
RE_SHA256 = r"\b[a-fA-F0-9]{64}\b"
RE_DOMAIN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

def defang_value(val: str, ioc_type: str) -> str:
    """Safely defang indicator for storage and display."""
    if ioc_type in ("ipv4", "domain"):
        return val.replace(".", "[.]").replace("http://", "hxxp://").replace("https://", "hxxps://")
    return val

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.replace("[.]", "."))
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False

def extract_and_score(text: str) -> list:
    extracted = []
    
    # 1. Hashes (SHA256)
    for h in set(re.findall(RE_SHA256, text)):
        extracted.append({
            "type": "sha256",
            "value": h.lower(),
            "defanged": h.lower(),
            "confidence": 90,
            "ttl_days": 180
        })
        
    # 2. IP Addresses (Standard and Defanged)
    raw_ips = re.findall(RE_IPV4, text) + [ip.replace("[.]", ".") for ip in re.findall(RE_DEFANGED_IP, text)]
    for ip in set(raw_ips):
        if is_public_ip(ip):
            extracted.append({
                "type": "ipv4",
                "value": ip,
                "defanged": defang_value(ip, "ipv4"),
                "confidence": 75,
                "ttl_days": 14
            })
            
    # 3. Domains
    for dom in set(re.findall(RE_DOMAIN, text)):
        if not dom.endswith((".exe", ".dll", ".zip", ".png", ".jpg", ".txt")) and "." in dom:
            extracted.append({
                "type": "domain",
                "value": dom.lower(),
                "defanged": defang_value(dom.lower(), "domain"),
                "confidence": 70,
                "ttl_days": 30
            })
            
    return extracted

if __name__ == "__main__":
    sample_text = """
    Incident 2026-10-07: Host infected via malicious dropper.
    C2 server located at 198.51.100.45 and secondary relay at 198.51.100.99.
    Payload sha256: 2c5a2c4e2b0c39f0d19e9188e404be12f00a29ef19a86a60e0a4f5b248a31e89
    Phishing domain used: evil-updates-cloud.example.com
    """
    results = extract_and_score(sample_text)
    print(f"Extracted {len(results)} indicators:")
    for r in results:
        print(f"  [{r['type'].upper():<6}] {r['defanged']:<35} Score: {r['confidence']} | TTL: {r['ttl_days']}d")
```

---

## 4. SIEM Ingestion & Aging Implementation

### Microsoft Defender XDR (KQL): Indicator Age Decay Query

```kql
// Query for active threat indicators where age-adjusted confidence remains above threshold
let CurrentTime = now();
ThreatIntelligenceIndicator
| where Active == true and ExpirationDateTime > CurrentTime
| extend AgeDays = datetime_diff('day', CurrentTime, TimeGenerated)
| extend AdjustedScore = toint(ConfidenceScore * exp(-0.05 * AgeDays))
| where AdjustedScore >= 50
| project TimeGenerated, IndicatorId, ThreatType, NetworkIP, DomainName, FileHashValue, ConfidenceScore, AdjustedScore, AgeDays
| sort by AdjustedScore desc
```

### Splunk (SPL): Threat Intel Pruning Workflow

```spl
| inputlookup threat_intel_master.csv
| eval current_epoch = now()
| eval age_days = round((current_epoch - first_seen_epoch) / 86400, 1)
| eval score_decay = case(
    type=="ipv4", confidence * exp(-0.099 * age_days),
    type=="domain", confidence * exp(-0.046 * age_days),
    type=="sha256", confidence * exp(-0.007 * age_days),
    true(), confidence
)
| where score_decay >= 40 AND age_days <= max_retention_days
| outputlookup threat_intel_master.csv
```

---

## 5. Defensive Operational Rules

1. **Defang in All Human Communications:** Never paste active URLs or executable IPs into tickets, chat channels, or Markdown documentation; always defang as `hxxps[://]` and `[.]`.
2. **Never Blacklist Without Telemetry Scrutiny:** Cross-reference candidate CTI IP lists against internal proxy and firewall logs for the preceding 30 days before pushing to firewall blocks to avoid dropping critical business SaaS or DNS relays.
3. **Automate Continuous Pruning:** Schedule nightly cron/scheduled jobs to recalculate decay scores and purge expired indicators from firewall and SIEM lookup stores.
