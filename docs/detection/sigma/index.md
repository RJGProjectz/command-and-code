---
title: Sigma
type: index
---

# Sigma

Sigma is a vendor-neutral YAML format for detection rules. One rule can be converted into SPL, KQL and other query languages — useful when you run Splunk **and** Defender, or want detections that survive a SIEM migration.

## Rule anatomy

```yaml
title: Short, specific title
id: 633f31d8-5c20-4c59-aafc-e84c923e4941      # UUID, never reused
status: experimental                          # experimental | test | stable
description: What it detects and why.
author: Your name
date: 2026-10-05
tags:
  - attack.persistence                        # ATT&CK tactic
  - attack.t1547.001                          # ATT&CK technique
logsource:
  category: process_creation                  # what kind of telemetry
  product: windows
detection:
  selection:
    Image|endswith: '\example.exe'            # field|modifier: value
    CommandLine|contains:                     # list = OR
      - 'value-one'
      - 'value-two'
  filter_legit:
    ParentImage|endswith: '\trusted.exe'
  condition: selection and not filter_legit
falsepositives:
  - Known legitimate cause
level: medium                                 # informational | low | medium | high | critical
```

| Concept | Rule |
| --- | --- |
| Keys inside one selection | AND |
| List of values for one key | OR |
| Common modifiers | `contains`, `startswith`, `endswith`, `re`, `all`, `base64offset`, `windash`, `cidr` |
| Common log source categories | `process_creation`, `network_connection`, `registry_set`, `file_event`, `dns_query`, `image_load`, `ps_script` |

## Convert rules with sigma-cli

```bash
pip install sigma-cli
sigma plugin list
sigma plugin install splunk
sigma plugin install kusto
sigma list targets
sigma list pipelines
sigma convert -t splunk -p splunk_windows rules/example.yml
```

Backend and pipeline names change between pySigma releases — `sigma list targets` and `sigma list pipelines` show what your installed plugins support. A pipeline maps Sigma's generic field names to your data's field names; without the right pipeline the converted query will search for fields that do not exist.

## Pages

- [Rule examples](examples.md) — encoded PowerShell, suspicious service installation, Run key persistence, schtasks creation
- [Cloud identity rules](cloud-identity-rules.md) — service principal credentials, OAuth consent, Entra ID
- Concept rules (each with KQL/SPL translations): [ARP spoofing (DAI)](arp-spoofing-dai.md) · [Network flood](dos-flood.md) · [LLMNR / NBT-NS poisoning](llmnr-nbtns-poisoning.md) · [Honeytoken use](honeytoken-access.md) · [Unmanaged mobile access](unmanaged-mobile-access.md) · [CI/CD secret leak](cicd-secret-leak.md) · [Wi-Fi (WLAN-AutoConfig)](wlan-events.md) · [Cryptomining](cryptomining.md)

## Everything tagged Sigma

<!-- cc:index languages="Sigma" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Detection Development Lifecycle (DDLC) and Testing](../../tasks/detection-engineering/detection-development-lifecycle.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, Sigma, PowerShell | Detection Engineering, Threat Hunting, Incident Response |
| [Detection-as-Code Pipeline (Version Control, CI Validation & Staged Deploy)](../../tasks/detection-engineering/detection-as-code-pipeline.md) | Workflow | Microsoft Defender, Splunk, SentinelOne, GitHub, Linux | Sigma, KQL, SPL, S1QL, Python, Bash | Detection Engineering, Automation, Assurance |
| [Detection Rule — ARP Spoofing (DAI and arpwatch)](arp-spoofing-dai.md) | Entry | Linux, Splunk | Sigma, SPL, KQL | Detection Engineering, Threat Hunting |
| [Detection Rule — CI/CD Secret Leak](cicd-secret-leak.md) | Entry | Splunk | Sigma, SPL, KQL | Detection Engineering, Incident Response |
| [Detection Rule — Cryptomining (Resource Hijacking)](cryptomining.md) | Entry | Windows, Linux, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — Honeytoken and Honey Account Use](honeytoken-access.md) | Entry | Active Directory, Windows Server, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — LLMNR / NBT-NS Poisoning](llmnr-nbtns-poisoning.md) | Entry | Windows, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — Network Flood (DoS / DDoS)](dos-flood.md) | Entry | Azure, Splunk | Sigma, KQL, SPL | Detection Engineering, Incident Response |
| [Detection Rule — Unmanaged Mobile Access to Corporate Apps](unmanaged-mobile-access.md) | Entry | Entra ID, Intune, Microsoft 365 | Sigma, KQL | Detection Engineering, Compliance |
| [Detection Rules — Wi-Fi (WLAN-AutoConfig and Unknown Devices)](wlan-events.md) | Entry | Windows, Windows Server | Sigma, KQL, SPL | Detection Engineering, Investigation |
| [Sigma Rule Examples](examples.md) | Entry | Windows | Sigma | Detection Engineering, Threat Hunting |
| [Sigma Rules for Cloud Identity and Entra ID Attacks](cloud-identity-rules.md) | Entry | Entra ID, Microsoft 365, Azure | Sigma | Detection Engineering, Threat Hunting |

<!-- /cc:index -->

## Sources

- [Sigma specification](https://github.com/SigmaHQ/sigma-specification)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
