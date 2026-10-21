---
title: Defensive
type: index
hide:
  - toc
---

# Defensive Security — Harden, Detect & Respond

Blue-team functions: reducing the attack surface, proving controls work, detecting adversary activity and
responding when it happens. The commands and theory these pages rely on live in
[Foundations](../foundations/index.md); the attacker's view of the same techniques is under
[Offensive](../offensive/index.md).

## Detection content

<div class="grid cards" markdown>

-   :material-database-search:{ .lg } **[Detection](../detection/index.md)**

    ---

    KQL, SPL, S1QL and Sigma queries and rules, mapped to MITRE ATT&CK.

</div>

## Harden & assure

<div class="grid cards" markdown>

-   :material-shield-lock-outline:{ .lg } **[Hardening](../tasks/hardening/index.md)**

    ---

    Logging, auditing, firewall, encryption and SSH configuration.

-   :material-clipboard-check-outline:{ .lg } **[Assurance](../tasks/assurance/index.md)**

    ---

    Read-only compliance checks: STIG, SCuBA, EDR health, sudoers, default-deny firewalls.

</div>

## Detect

<div class="grid cards" markdown>

-   :material-radar:{ .lg } **[Detection Engineering](../tasks/detection-engineering/index.md)**

    ---

    Build, deploy and tune detections and the telemetry behind them.

-   :material-crosshairs-gps:{ .lg } **[Threat Hunting](../tasks/threat-hunting/index.md)**

    ---

    Hypothesis-driven hunts such as lateral movement.

-   :material-earth:{ .lg } **[Threat Intelligence](../tasks/threat-intelligence/index.md)**

    ---

    STIX/TAXII feeds, adversary emulation and IoC lifecycle scoring.

</div>

## Respond

<div class="grid cards" markdown>

-   :material-alarm-light-outline:{ .lg } **[Incident Response](../tasks/incident-response/index.md)**

    ---

    Endpoint triage, suspicious PowerShell and processes, malware, account compromise.

-   :material-magnify:{ .lg } **[Investigation](../tasks/investigation/index.md)**

    ---

    Services, scheduled tasks, registry persistence, failed authentication, network connections.

-   :material-fingerprint:{ .lg } **[Forensics](../tasks/forensics/index.md)**

    ---

    Evidence preservation and artifacts.

</div>
