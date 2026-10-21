---
title: Offensive
type: index
hide:
  - toc
---

# Offensive Security — Assessment & Enumeration

Authorized offensive work: finding the weaknesses in a system **before** an attacker does, so they
can be fixed. These pages are the practical, tool-driven counterpart to the offensive **theory** that
already lives in [Concepts](../fundamentals/concepts/index.md) and the defensive controls in
[Web Applications & OWASP](../fundamentals/web-apps/owasp-web-top-10.md).

> [!WARNING]
> **Authorized testing only.** Every technique here generates traffic against a target. Run them
> **only** against systems you own or have explicit, written permission to test (a signed engagement,
> a scoped bug-bounty program, or your own lab). Unauthorized scanning and enumeration may be illegal
> — see [Cyber Law](../fundamentals/concepts/cyber-law.md) and
> [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md). Stay inside the agreed
> scope, rate, and time window, and keep an audit trail of what you ran.

## Where this fits — the assessment lifecycle

| Phase | Question it answers | On this site |
| :--- | :--- | :--- |
| **Reconnaissance** | What exists, and who owns it? (passive) | [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) |
| **Enumeration** | What services, versions, and content are exposed? | [Web Application Assessment](web-application-assessment.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md) |
| **Vulnerability identification** | Which exposed things are weak? | [Web Application Assessment](web-application-assessment.md) · [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md) |
| **Reporting** | What did we find, how bad is it, how is it fixed? | [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md) |

These pages focus on **recon, enumeration, and fingerprinting** — identifying what is there and how
exposed it is. Exploitation technique belongs in a scoped engagement; the defensive fixes for what you
find are documented under [Reference → Web Applications & OWASP](../fundamentals/web-apps/owasp-web-top-10.md).

## Pages

<!-- cc:index tasks="Assessment" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Enumerate a Web Application for Technology, Versions and Weaknesses](web-application-assessment.md) | Workflow | Linux | Bash | Assessment |

<!-- /cc:index -->

## Related reading

- **Theory:** [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md) · [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md) · [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md)
- **Defensive counterparts:** [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) · [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md)
- **Detect it:** the [Detection](../detection/index.md) tab holds the queries and rules that catch scanning and enumeration against your own estate.
