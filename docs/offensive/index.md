---
title: Offensive
type: index
hide:
  - toc
---

# Offensive Security — Assessment & Enumeration

Authorized offensive work: finding the weaknesses in a system **before** an attacker does, so they
can be fixed. These pages are the practical, tool-driven counterpart to the offensive **theory** that
already lives in [Concepts](../fundamentals/concepts/index.md), and the blue-team view of the same
techniques under [Defensive](../defensive/index.md).

> [!WARNING]
> **Authorized testing only.** Every technique here generates traffic against a target. Run them
> **only** against systems you own or have explicit, written permission to test (a signed engagement,
> a scoped bug-bounty program, or your own lab). Unauthorized scanning and enumeration may be illegal
> — see [Cyber Law](../fundamentals/concepts/cyber-law.md) and
> [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md). Stay inside the agreed
> scope, rate, and time window, and keep an audit trail of what you ran.

## The red-team lifecycle — by stage

This track is organised by the **five stages of an authorized red-team engagement**, the offensive
mirror of the Defensive tab's categories. Because this project is **assessment/enumeration-only**, the
stages that turn weaponized in a real intrusion — Command-and-Control, defense evasion, exfiltration —
are documented as **what to know and how to detect/harden**, never as attack tooling, implants or
payloads.

<div class="grid cards" markdown>

-   :material-binoculars:{ .lg } **[Stage 1 — Reconnaissance](osint-active-recon.md)**

    ---

    Gather OSINT, map the estate, and scan networks and public/internal entry points — passively first.

    [OSINT & Active Recon](osint-active-recon.md) · [Passive Web OSINT (Tool)](passive-web-osint.md) ·
    [Network & Infrastructure Enumeration](network-infrastructure-enumeration.md) ·
    [Wi-Fi / Wireless Assessment](wifi-wireless-assessment.md) ·
    [Cloud Attack Surface](cloud-attack-surface-enumeration.md) ·
    [Container & Kubernetes Attack Surface](container-kubernetes-attack-surface.md)

-   :material-login-variant:{ .lg } **[Stage 2 — Initial Access](web-application-assessment.md)**

    ---

    Find and validate the ways in — exposed services, web/API weaknesses, weak credentials, people.

    [Web Application Assessment](web-application-assessment.md) ·
    [Web API Assessment](web-api-assessment.md) · [API Surface Recon (Tool)](api-surface-recon-tool.md) ·
    [LLM Application Assessment](llm-application-assessment.md) ·
    [Password Attacks & Credential Cracking](password-attacks-credential-cracking.md) ·
    [Phishing & Social-Engineering Simulation](phishing-social-engineering-ops.md)

-   :material-access-point:{ .lg } **[Stage 3 — Foothold & Command-and-Control](foothold-command-control.md)**

    ---

    How an adversary persists, calls home, and evades defences — **covered for awareness and defence,
    not operation** (no C2, implants or persistence tooling).

    [Persistence mechanisms](foothold-command-control.md#1-persistence-mechanisms-scheduled-tasks-services-run-keys) ·
    [C2 channels & beaconing](foothold-command-control.md#2-command-and-control-channels-beaconing) ·
    [Defense evasion / AMSI](foothold-command-control.md#3-defense-evasion-amsi-logging-tamper-living-off-the-land)

-   :material-stairs-up:{ .lg } **[Stage 4 — Lateral Movement & Privilege Escalation](windows-host-enumeration-privesc.md)**

    ---

    Move deeper and escalate — assessed by enumerating the paths that make it possible.

    [Windows Host Enum & Privesc](windows-host-enumeration-privesc.md) ·
    [Linux Host Enum & Privesc](linux-host-enumeration-privesc.md) ·
    [Active Directory Enumeration](active-directory-enumeration.md)

-   :material-flag-checkered:{ .lg } **[Stage 5 — Actions on Objectives & Reporting](actions-on-objectives-reporting.md)**

    ---

    Prove the objective with the least intrusive evidence, assess business impact, and deliver the
    report — **simulated impact only, no exfiltration tooling**.

    [Data-access simulation & evidence](actions-on-objectives-reporting.md#1-data-access-simulation-proof-of-access-evidence) ·
    [Impact assessment](actions-on-objectives-reporting.md#2-impact-assessment) ·
    [Engagement reporting & remediation hand-off](actions-on-objectives-reporting.md#3-engagement-reporting-remediation-hand-off)

</div>

## Pages

<!-- cc:index tasks="Assessment" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Actions on Objectives & Reporting — Simulated Impact and Engagement Deliverables](actions-on-objectives-reporting.md) | Workflow | Windows, Linux | — | Assessment |
| [Assess a Web API for Endpoints, Authorization Flaws and Abuse](web-api-assessment.md) | Workflow | Linux | Bash, HTTP | Assessment |
| [Assess a Wi-Fi Network's Posture — Survey, Encryption and Rogue-AP Awareness](wifi-wireless-assessment.md) | Workflow | Linux | Bash | Assessment |
| [Assess an LLM Application for Prompt Injection and Abuse](llm-application-assessment.md) | Workflow | Linux | Python, HTTP | Assessment |
| [Assess Credential Strength — Authorized Password Spraying and Offline Hash Cracking](password-attacks-credential-cracking.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate a Linux Host and Identify Privilege-Escalation Paths](linux-host-enumeration-privesc.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate a Web Application for Technology, Versions and Weaknesses](web-application-assessment.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate a Windows Host and Identify Privilege-Escalation Paths](windows-host-enumeration-privesc.md) | Workflow | Windows | PowerShell | Assessment |
| [Enumerate Active Directory for Users, Privileges and Attack Paths](active-directory-enumeration.md) | Workflow | Active Directory, Windows | PowerShell, Bash | Assessment |
| [Enumerate an Internal Network and its Services](network-infrastructure-enumeration.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate Cloud Attack Surface across AWS, Azure and GCP](cloud-attack-surface-enumeration.md) | Workflow | AWS, Azure, GCP | Bash, Python | Assessment |
| [Enumerate Container and Kubernetes Attack Surface — Exposed Runtimes, kubelet, API Server and RBAC](container-kubernetes-attack-surface.md) | Workflow | Linux | Bash, Python | Assessment |
| [Foothold, Command-and-Control & Defense Evasion — Awareness, Detection and Hardening](foothold-command-control.md) | Workflow | Windows, Linux | — | Assessment |
| [Map an Organization's Attack Surface with OSINT and Active Reconnaissance](osint-active-recon.md) | Workflow | Linux | Bash | Assessment |
| [Run an Authorized Phishing Simulation — Measure Human and Technical Susceptibility](phishing-social-engineering-ops.md) | Workflow | Linux | Bash | Assessment |
| [API Surface Recon Tool (scope- and rate-limit-aware)](api-surface-recon-tool.md) | Tool | Linux | Bash | Assessment |
| [Passive Web OSINT Tool (one or many targets)](passive-web-osint.md) | Tool | Linux | Bash | Assessment |

<!-- /cc:index -->

## Related reading

- **Theory:** [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md) · [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md) · [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md)
- **Defensive counterparts:** [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) · [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md)
- **Detect it:** the [Detection](../detection/index.md) tab holds the queries and rules that catch scanning and enumeration against your own estate.
