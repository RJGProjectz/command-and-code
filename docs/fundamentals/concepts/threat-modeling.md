---
title: Threat Modeling
type: concept
platforms: [Windows, Linux]
languages: [Python]
tasks: [Assessment, Hardening, Detection Engineering]
category: Security Operations
security_domain: Application
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [threat-modeling, STRIDE, DREAD, attack-tree, data-flow-diagram, DFD, security-architecture, PASTA, VAST, misuse-case]
aliases: [threat analysis, STRIDE, attack trees, threat model, security design, threat identification]
difficulty: intermediate
verified: false
---

# Threat Modeling
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** threat modeling is a structured process for identifying what can go wrong in a system and deciding what controls to apply — before an attacker finds the answer first.

## What it is

Threat modeling is an architectural practice that systematically surfaces threats during the design phase of a system — the point at which they are cheapest to address. Rather than reacting to incidents, a team walks through a visual representation of the system, asks where an adversary could cause harm, and documents countermeasures before a line of production code is written.

The output of a threat model is not a list of vulnerabilities but a map of threats with associated risk levels and mitigations. It feeds directly into security requirements, architecture decisions, and penetration test scope.

Threat modeling applies equally to new systems being designed and to existing systems undergoing significant change (new integrations, cloud migration, scope expansion). It is a repeating activity, not a one-time exercise — the threat landscape, system design, and data flows change over time.

## How it works

A threat modeling session typically follows five steps:

1. **Define the scope** — agree which system component, user story, or data flow is under analysis.
2. **Decompose the system** — create a Data Flow Diagram (DFD) or component architecture diagram showing actors, processes, data stores, and the boundaries between trust zones.
3. **Identify trust boundaries** — draw where data crosses from one trust level to another (external internet → DMZ → internal network; browser → API → database). Every boundary is a potential attack surface.
4. **Identify threats** — apply a structured technique (STRIDE, attack trees, or OWASP Top Ten) to each boundary and component.
5. **Document mitigations** — for each threat, record whether the control is: already implemented, planned, accepted as a risk, or not applicable.

The artifacts produced — a DFD, threat register, and mitigation table — become reference material for the development team, security reviewers, and penetration testers.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | Threat modeling reduces exposure across all tactics — it is a prevention practice, not a detection technique |
| **What it prevents** | Design-level flaws: missing authentication, unencrypted data stores, over-privileged service accounts — issues that are expensive to fix post-deployment |
| **Where defenders meet it** | Architecture review, Secure SDLC gating, pen test scoping, and compliance exercises (PCI DSS, SOC 2, FedRAMP) |

## Key Methodologies

### STRIDE

STRIDE was developed at Microsoft in 1999 by Loren Kohnfelder and Praerit Garg. Each letter targets a different threat category:

| Letter | Threat | Example |
| :--- | :--- | :--- |
| **S**poofing | Attacker impersonates a user, system, or service | Forged JWT token claims a privileged role |
| **T**ampering | Unauthorized modification of data or code | Log records altered to cover an attack |
| **R**epudiation | Actor denies performing an action | Service account with no audit trail deletes a record |
| **I**nformation disclosure | Sensitive data exposed to unauthorized parties | S3 bucket set to public-read contains PII |
| **D**enial of service | System availability disrupted | Unthrottled API endpoint consumed by a bot flood |
| **E**levation of privilege | Attacker gains rights beyond their authorization | SQL injection bypasses row-level access controls |

The goal is not to categorize threats perfectly but to use the categories as a brainstorming prompt. A card game called **Elevation of Privilege (EoP)**, published by Microsoft as an open-source resource, turns STRIDE into a structured group activity.

### Attack Trees

An attack tree is a hierarchical diagram where the root node is the attacker's goal (e.g., "Exfiltrate the customer database") and child nodes represent sub-goals or individual steps the attacker must achieve. AND-nodes require all children to succeed; OR-nodes require at least one.

Attack trees are especially useful for:
- Reasoning about the cost or difficulty of an attack path
- Comparing the risk reduction of different mitigations
- Communicating risk to non-technical stakeholders visually

### PASTA (Process for Attack Simulation and Threat Analysis)

PASTA is a risk-centric, seven-stage methodology that aligns threat modeling output to business impact. It moves from defining business objectives through application decomposition to threat enumeration and residual risk analysis. PASTA is more comprehensive than STRIDE alone and suits regulated environments where threat models must map to compliance requirements.

### VAST (Visual, Agile, and Simple Threat)

VAST integrates threat modeling into Agile development workflows. It defines two model types: application threat models (DFD-based, for development) and operational threat models (infrastructure-focused, for operations). VAST suits teams that need to produce threat models at the pace of a sprint cycle.

## Do it

Run an ad-hoc STRIDE session on a component you own:

```bash
# cc toolbox lookup
cc find "data flow diagram"
cc view fundamentals/concepts/threat-modeling.md
```

To automate threat model generation, use the OWASP Threat Dragon (open-source, browser-based) or Microsoft Threat Modeling Tool (Windows desktop):

```bash
# Install OWASP Threat Dragon via npm
npm install -g threat-dragon
threat-dragon
```

For team sessions, use the Microsoft EoP card game or a structured whiteboard session:

1. Draw the DFD on a shared whiteboard or Miro board
2. Walk each trust boundary with the STRIDE acronym
3. Record each threat in a simple table: Component, Threat category, Description, Mitigation, Status

## See it

Threat modeling evidence appears in:

| Source | What you see |
| :--- | :--- |
| Architecture review records | DFD diagrams with labeled trust boundaries and threat annotations |
| Security requirements documents | "The API must authenticate all requests" — derived from a STRIDE-S finding |
| Pen test scope documents | Sections labelled "Known threat model areas to validate" |
| JIRA / ADO sprint backlogs | Security stories with `threat-model` label |

## Detect it

Threat modeling is a design-phase control; you detect its *absence* through audit, not through runtime events:

- Assurance: [Security Assurance and Review](../../tasks/assurance/index.md)
- Harden: [Secure SDLC, DevSecOps and Secure Coding](secure-sdlc-devsecops.md)
- Respond: when an incident's root cause traces to a design-level flaw, a threat model update is the remediation

## Related concepts

- [Secure SDLC, DevSecOps and Secure Coding](secure-sdlc-devsecops.md)
- [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- [Penetration Testing and Red Teaming](penetration-testing.md)
- [Defense in Depth](defense-in-depth.md)
- [Zero Trust Architecture](zero-trust.md)

## External Resources

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [Microsoft EoP Card Game (GitHub)](https://github.com/adamshostack/EoP)
- [PASTA Methodology (WhiteHat Security)](https://www.owasp.org/images/a/aa/AppSecEU2012_PASTA.pdf)
- [NIST SP 800-154: Guide to Data-Centric System Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)
