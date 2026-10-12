---
title: Secure SDLC, DevSecOps and Secure Coding
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash, Python]
tasks: [Hardening, Assurance, Automation]
category: Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, sdlc, devsecops, secure-coding, supply-chain]
aliases: [Software Development Life Cycle, Software Development Life Cycle Security, DevSecOps, DevOps, Secure Coding Practices, How to Conduct a Secure Code Review, Dependency Management, Application Security Tools, Application Vulnerability Testing, High-Level Languages, Low-Level Languages]
difficulty: intermediate
verified: false
---

# Secure SDLC, DevSecOps and Secure Coding
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** security is cheapest when built into every phase of software delivery — requirements, design, code, build, test, deploy — and automated in the pipeline.

## What it is

**SDLC phases:** requirements → design → implementation → testing → deployment → maintenance. A **secure SDLC** adds
security work to each (frameworks: NIST SSDF SP 800-218, OWASP SAMM, Microsoft SDL). **DevOps** joins development and
operations with automated CI/CD; **DevSecOps** puts the security checks into that pipeline ("shift left").

| Practice | Finds | Example tools |
| :--- | :--- | :--- |
| Threat modelling (STRIDE) | design flaws | diagrams + checklist |
| **SAST** (static analysis) | injection, unsafe APIs in source | Semgrep, CodeQL, PSScriptAnalyzer |
| **SCA** (dependency scanning) | vulnerable / malicious libraries | Dependabot, `npm audit`, `pip-audit`, Trivy |
| Secrets scanning | keys and passwords in code | gitleaks, GitHub secret scanning |
| **DAST** | runtime flaws in the running app | OWASP ZAP |
| SBOM | what is inside the build | CycloneDX, SPDX |

**Languages:** low-level languages (C, C++) give direct memory control and cause most memory-safety bugs (buffer
overflows, use-after-free); high-level, memory-safe languages (Rust, Go, C#, Java, Python) remove whole classes of them —
the reason governments now push memory-safe roadmaps.

## How it works

**Secure coding basics:** validate input and encode output ([XSS](../web-apps/xss-defense.md)), parameterised queries
([SQL injection](../web-apps/sql-injection.md)), least-privilege service identities, no secrets in code, safe
defaults, log security events without sensitive data, handle errors without leaking internals.

**Secure code review:** focus on trust boundaries — authentication, authorisation checks on every request, input
handling, crypto use, file and command execution, deserialisation; combine a SAST pass with human review of the risky diffs.

**Dependency management:** lock files and pinned versions, update regularly, verify publishers, watch for typosquatting
and dependency-confusion (internal package names resolved from public registries).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) Compromise Software Dependencies · [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application · [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Credentials in Files |
| **What it leads to** | supply-chain compromise (SolarWinds, xz-utils), leaked cloud keys, exploitable web apps |
| **Where defenders meet it** | pipeline gates, leaked-secret alerts, vulnerable-library advisories |

## Do it

```powershell
# Static analysis for PowerShell code in this repo
Invoke-ScriptAnalyzer -Path .\scripts -Recurse -Severity Warning, Error
```

```bash
# Dependency vulnerabilities
npm audit --omit=dev
pip-audit -r requirements.txt
# Secrets accidentally committed (whole history)
gitleaks detect --source . --redact
# Filesystem / lockfile scan with SBOM output
trivy fs --scanners vuln,secret --format cyclonedx --output sbom.json .
```

## See it

| Source | What you see |
| :--- | :--- |
| CI pipeline results | SAST/SCA findings blocking a merge |
| Repository security tab | Dependabot alerts, secret-scanning alerts |
| SBOM | every component and version shipped — answer "are we affected?" in minutes |

## Detect it

- Web flaws: [OWASP Web Top 10](../web-apps/owasp-web-top-10.md) · [SQL injection](../web-apps/sql-injection.md) · [XSS defense](../web-apps/xss-defense.md)
- Automation: [Automation tasks](../../tasks/automation/index.md)
- No dedicated rule page yet for CI/CD secret-leak alerts (tracked in WP-31).

## Related concepts

- [Vulnerability Management](vulnerability-management.md) · [Cloud-Native Security](cloud-native-security.md) · [Digital Signatures](digital-signatures.md)
