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

!!! tip "Interactive Themes Available"
    Customize your field manual view in the top header: choose between 🛡️ **Classic** (Field Manual), 🔮 **Nexus Cyber** (Cyberpunk Synthwave), or ⚡ **Electric Cyber** (High-Voltage Grid).

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

</div>

## Browse by Platform

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

-   :material-server-network:{ .lg } **[Virtualization](platforms/virtualization/index.md)**

    ---

    Hyper-V · VMware · Proxmox

</div>

## Browse by Language / Technology

<div class="grid cards" markdown>

-   :material-powershell:{ .lg } **[PowerShell](languages/powershell/index.md)** · **[Bash](languages/bash/index.md)** · **[Python](languages/python/index.md)**

    ---

    Commands, data handling, APIs, error handling and automation — including the pitfalls that break scripts.

-   :material-magnify-scan:{ .lg } **[KQL](detection/kql/index.md)** · **[SPL](detection/spl/index.md)** · **[S1QL](detection/s1ql/index.md)**

    ---

    Hunting and detection queries for Defender XDR, Sentinel, Splunk and SentinelOne — plus [Sigma](detection/sigma/index.md) and [ATT&CK](detection/mitre-attack/index.md).

</div>

## Browse by Task

<div class="grid cards" markdown>

-   :material-alarm-light-outline:{ .lg } **[Incident Response](tasks/incident-response/index.md)**

    ---

    [Endpoint triage](tasks/incident-response/endpoint-triage.md) · [Suspicious PowerShell](tasks/incident-response/suspicious-powershell.md) · [Account compromise](tasks/incident-response/account-compromise.md)

-   :material-crosshairs-gps:{ .lg } **[Threat Hunting](tasks/threat-hunting/index.md)** · **[Investigation](tasks/investigation/index.md)**

    ---

    [Lateral movement](tasks/threat-hunting/lateral-movement.md) · [Failed authentication](tasks/investigation/failed-authentication.md) · [Outbound connections](tasks/investigation/suspicious-outbound-connection.md)

-   :material-radar:{ .lg } **[Detection Engineering](tasks/detection-engineering/index.md)** · **[Automation](tasks/automation/index.md)**

    ---

    Queries, Sigma rules and the [toolbox](toolbox/index.md) of reusable scripts.

-   :material-wrench-outline:{ .lg } **[Administration](tasks/administration/index.md)** · **[Troubleshooting](tasks/troubleshooting/index.md)**

    ---

    Configuration locations, health checks and fault-finding workflows.

</div>

---

**The repository is the product.** Everything here is Markdown and scripts in Git — readable offline, in VS Code, on GitHub, or as this site. See the [roadmap](roadmap.md) for where it is going and the [metadata conventions](references/metadata.md) for how to add to it.
