---
title: Automated IoC Enrichment and Threat Intelligence Pipeline
type: workflow
platforms:
  - Linux
  - Windows
languages:
  - PowerShell
  - Python
  - REST API
tasks:
  - Automation
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: intermediate
tags:
  - automation
  - ioc
  - enrichment
  - abuseipdb
  - virustotal
  - threat-intelligence
  - triage
---

# Automated IoC Enrichment and Threat Intelligence Pipeline

When alerts fire with external IP addresses, domain names, or file hashes, manual lookup burns precious triage time. This workflow automates multi-engine reputation queries to deliver actionable enrichment data directly to analysts.

---

## 1. Multi-Engine Lookup Architecture

```text
Alert Trigger (SIEM / EDR)
    ↓
Extract Observable (IP / SHA-256 / Domain)
    ↓
[Parallel API Queries]
    ├── AbuseIPDB API (IP Confidence Score, Report Count, Country)
    ├── VirusTotal v3 API (Malicious Vendor Detections, Sandbox Tags)
    └── AlienVault OTX API (Active Threat Pulses, Malware Families)
    ↓
Aggregate Severity Verdict
    ├── If Confidence > 75% OR VT Detections >= 5 => Auto-Isolate & Alert High
    └── If Benign / Known CDN => Contextual Tagging Only
```

---

## 2. PowerShell Automated Enrichment Script

This script queries the AbuseIPDB v2 REST API to evaluate an IP observable:

```powershell
function Get-IPEnrichment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiKey = $env:ABUSEIPDB_API_KEY
    )

    if (-not $ApiKey) {
        throw "AbuseIPDB API key is missing. Set `$env:ABUSEIPDB_API_KEY."
    }

    $Headers = @{
        "Key"    = $ApiKey
        "Accept" = "application/json"
    }

    $Url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IPAddress&maxAgeInDays=90&verbose"

    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Get -Headers $Headers
        $Data = $Response.data

        [PSCustomObject]@{
            IPAddress         = $Data.ipAddress
            IsPublic          = $Data.isPublic
            AbuseScore        = "$($Data.abuseConfidenceScore)%"
            TotalReports      = $Data.totalReports
            CountryCode       = $Data.countryCode
            UsageType         = $Data.usageType
            ISP               = $Data.isp
            Domain            = $Data.domain
            LastReportedAt    = $Data.lastReportedAt
            IsHighRisk        = ($Data.abuseConfidenceScore -ge 50)
        }
    }
    catch {
        Write-Error "Failed to enrich IP ${IPAddress}: $_"
    }
}

# Example Usage:
# Get-IPEnrichment -IPAddress "198.51.100.45"
```

---

## 3. Python Multi-Observable Enrichment Engine

A modular Python script to enrich SHA-256 file hashes via the VirusTotal v3 REST API:

```python
#!/usr/bin/env python3
"""Enrich file hashes against VirusTotal v3 API."""

import os
import sys
import json
import urllib.request
import urllib.error

VT_API_KEY = os.environ.get("VT_API_KEY")

def enrich_file_hash(sha256: str) -> dict:
    if not VT_API_KEY:
        raise ValueError("VT_API_KEY environment variable is not set.")

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "sha256": sha256,
                "meaningful_name": attributes.get("meaningful_name", "N/A"),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "reputation": attributes.get("reputation", 0),
                "verdict": "MALICIOUS" if stats.get("malicious", 0) >= 5 else "BENIGN"
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"sha256": sha256, "verdict": "UNKNOWN_NOT_FOUND"}
        raise

if __name__ == "__main__":
    test_hash = sys.argv[1] if len(sys.argv) > 1 else "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = enrich_file_hash(test_hash)
    print(json.dumps(result, indent=2))
```

---

## 4. Operational Best Practices

1. **Local Redis / In-Memory Cache**: Cache IoC lookups for 24 hours. Querying identical C2 IPs across 10,000 proxy events exhausts API quotas in minutes.
2. **Defang Output in Logs**: Automatically replace `.` with `[.]` and `http` with `hxxp` when publishing IoCs to ticketing systems to prevent accidental user clicks.
3. **Handle Private RFC 1918 Ranges**: Filter out `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` before transmitting queries to external intelligence APIs to avoid leaking internal topology.
