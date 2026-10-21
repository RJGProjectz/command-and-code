---
type: index
hide:
  - navigation
  - toc
search:
  boost: 0.5
---

<div class="cc-hero" markdown>

<p class="cc-kicker">Security operations field manual</p>

# Command & Code

<p class="cc-tagline"><strong>The practical security operations field manual.</strong></p>

A version-controlled knowledge base of **commands, code, queries, configuration locations, investigation procedures, detections and automation** — written for the analyst, administrator, detection engineer or incident responder who needs the answer now.

<div style="margin: 0.8rem 0 1.2rem;" markdown>
[:material-file-document-outline: **Executive Summary** — *Why this KB exists & how it works*](executive-summary.md){ .md-button .md-button--primary }
[:material-map-legend: Roadmap](roadmap.md){ .md-button }
</div>

<div id="cc-recent" class="cc-recent" hidden></div>

Press ++s++ or ++slash++ to search, or try:

<div class="cc-searches" markdown>
[listening ports](?q=listening+ports)
[suspicious powershell](?q=suspicious+powershell)
[failed windows login](?q=failed+windows+login)
[find process by PID](?q=find+process+by+PID)
[scheduled task persistence](?q=scheduled+task+persistence)
[registry run keys](?q=registry+run+keys)
[defender process query](?q=defender+process+query)
[linux services](?q=linux+services)
[network connections](?q=network+connections)
</div>

</div>

## What are you doing right now?

Pick the lane that matches the job in front of you. Each lane opens with the first three workflows to run; the count is every entry tagged for that task.

<div class="grid cards cc-lanes" markdown>

-   :material-alarm-light-outline:{ .lg } **[Responding to an incident](tasks/incident-response/index.md)** <span class="cc-lane-count"><!-- cc:count tasks="Incident Response" -->155<!-- /cc:count --> entries</span>

    ---

    1. [Triage the endpoint](tasks/incident-response/endpoint-triage.md) — capture volatile state
    2. [Check the account](tasks/incident-response/account-compromise.md) — sign-ins, tokens, mailbox rules
    3. [Isolate the host](tasks/incident-response/ransomware-host-isolation.md) — contain before it spreads

-   :material-magnify:{ .lg } **[Investigating a question](tasks/investigation/index.md)** <span class="cc-lane-count"><!-- cc:count tasks="Investigation" -->186<!-- /cc:count --> entries</span>

    ---

    1. [Failed authentication](tasks/investigation/failed-authentication.md) — who, from where, how often
    2. [Suspicious outbound connection](tasks/investigation/suspicious-outbound-connection.md) — process to destination
    3. [Registry persistence](tasks/investigation/registry-persistence.md) — run keys and services

-   :material-crosshairs-gps:{ .lg } **[Hunting for threats](tasks/threat-hunting/index.md)** <span class="cc-lane-count"><!-- cc:count tasks="Threat Hunting" -->86<!-- /cc:count --> entries</span>

    ---

    1. [Frame a hypothesis](tasks/threat-hunting/hypothesis-driven-hunting-framework.md) — scope, data, success criteria
    2. [Lateral movement](tasks/threat-hunting/lateral-movement.md) — remote logons and admin shares
    3. [LOLBin execution](tasks/threat-hunting/lolbins-execution-hunting.md) — signed binaries doing odd things

-   :material-wrench-outline:{ .lg } **[Fixing something broken](tasks/troubleshooting/index.md)** <span class="cc-lane-count"><!-- cc:count tasks="Troubleshooting" -->76<!-- /cc:count --> entries</span>

    ---

    1. [Network and domain connectivity](tasks/troubleshooting/windows-connectivity.md) — DNS, routes, ports, Kerberos
    2. [Service will not start](tasks/troubleshooting/linux-service-failure.md) — crashloops, SELinux, port conflicts
    3. [High CPU](tasks/troubleshooting/high-cpu-troubleshooting.md) — runaway process or miner?

</div>

**Other lanes:**

<div class="cc-searches cc-lane-chips" markdown>
[Forensics · <!-- cc:count tasks="Forensics" -->52<!-- /cc:count -->](tasks/forensics/index.md)
[Detection engineering · <!-- cc:count tasks="Detection Engineering" -->70<!-- /cc:count -->](tasks/detection-engineering/index.md)
[Hardening · <!-- cc:count tasks="Hardening" -->159<!-- /cc:count -->](tasks/hardening/index.md)
[Administration · <!-- cc:count tasks="Administration" -->186<!-- /cc:count -->](tasks/administration/index.md)
[Automation · <!-- cc:count tasks="Automation" -->57<!-- /cc:count -->](tasks/automation/index.md)
[Assurance · <!-- cc:count tasks="Assurance" -->71<!-- /cc:count -->](tasks/assurance/index.md)
[Threat intelligence · <!-- cc:count tasks="Threat Intelligence" -->11<!-- /cc:count -->](tasks/threat-intelligence/index.md)
[All tasks](tasks/index.md)
</div>

## Fast-Track & Cheat Sheets

<div class="grid cards" markdown>

-   :material-lightning-bolt:{ .lg } **[Sysadmin Quick Reference](references/sysadmin-cheat-sheet.md)**

    ---

    Side-by-side Windows vs. Linux lookup for host identity, services, storage, networking, and reboot recipes.

-   :material-powershell:{ .lg } **[PowerShell One-Liners](references/powershell-cheat-sheet.md)**

    ---

    High-yield one-liners for inventory, Active Directory, CIM hardware queries, event log audits, and PSRemoting.

-   :material-bash:{ .lg } **[Linux Speed Dial](references/linux-cheat-sheet.md)**

    ---

    Essential commands for systemd units, journalctl time filters, disk space, open socket inspection, and SUID checks.

-   :material-compare-horizontal:{ .lg } **[Cross-Platform Equivalents](references/equivalents.md)**

    ---

    Translate the same operational task across PowerShell, Bash, KQL, SPL, and S1QL.

-   :material-format-list-bulleted:{ .lg } **[Command Index — All Shells](references/command-index.md)**

    ---

    Everyday commands in PowerShell, CMD and Bash side by side, including shell history.

</div>

## Platforms

<div class="grid cards" markdown>

-   :material-microsoft-windows:{ .lg } **[Windows](platforms/windows/index.md)**

    ---

    Processes · services · networking · event logs · registry · tasks · Defender

-   :material-linux:{ .lg } **[Linux](platforms/linux/index.md)**

    ---

    Processes · systemd · networking · logs · cron · SSH · permissions

-   :material-microsoft:{ .lg } **[Microsoft 365](platforms/microsoft-365/index.md)**

    ---

    Defender XDR · Entra ID · Conditional Access · Intune · Exchange Online

-   :material-cloud-outline:{ .lg } **[Azure](platforms/azure/index.md)** · **[AWS](platforms/aws/index.md)** · **[Google Cloud](platforms/gcp/index.md)**

    ---

    Identity, compute, networking, storage, audit logs, keys, Kubernetes and posture, with the same topics across all three clouds.

-   :material-server-network:{ .lg } **[Virtualization](platforms/virtualization/index.md)**

    ---

    Hyper-V · VMware · Proxmox

</div>

## Shells & Scripting

<div class="grid cards" markdown>

-   :material-powershell:{ .lg } **[PowerShell](languages/powershell/index.md)** · **[Bash](languages/bash/index.md)** · **[CMD](languages/windows-cli/index.md)** · **[Python](languages/python/index.md)**

    ---

    Commands, batch and shell scripting, APIs, text processing, error handling and automation.

-   :material-magnify-scan:{ .lg } **[KQL](detection/kql/index.md)** · **[SPL](detection/spl/index.md)** · **[S1QL](detection/s1ql/index.md)**

    ---

    Hunting and detection queries for Defender XDR, Sentinel, Splunk and SentinelOne — plus [Sigma](detection/sigma/index.md) and [ATT&CK](detection/mitre-attack/index.md).

</div>

---

**The repository is the product.** Everything here is Markdown and scripts in Git — readable offline, in VS Code, on GitHub, or as this site. See the [Executive Summary](executive-summary.md) for the operational philosophy, the [roadmap](roadmap.md) for where it is going, and the [metadata conventions](references/metadata.md) for how to add to it.
