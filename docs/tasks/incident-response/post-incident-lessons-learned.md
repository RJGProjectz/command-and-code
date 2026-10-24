---
title: Post-Incident Activity and Lessons Learned
type: workflow
platforms: [Windows, Linux, Microsoft 365]
languages: [KQL]
tasks: [Incident Response, Detection Engineering, Hardening]
category: Workflow
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-24
last_updated: 2026-10-24
tags: [incident-response, post-incident, lessons-learned, after-action-review, root-cause, timeline, mttd, mttr, metrics, remediation-tracking, feedback-loop, nist-800-61, lifecycle]
aliases: [post-incident activity, lessons learned, after action review, AAR, hotwash, incident retrospective, root cause analysis, incident timeline, MTTD MTTR, incident metrics, remediation tracking, feedback loop detection engineering, how to close an incident]
difficulty: intermediate
verified: false
---

# Post-Incident Activity and Lessons Learned
> **Created**: 2026-10-24T00:00:00Z
> **Last Modified**: 2026-10-24T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: HANDLE INCIDENT DATA WITH CARE**
> This phase produces the incident record and drives changes back into production detection and
> hardening. Before you share or act:
> 1. Keep the review **blameless** — the goal is systemic improvement, not individual fault.
> 2. Treat the timeline, root cause and metrics as **sensitive**; share on need-to-know and follow
>    retention, legal-hold and regulatory-notification policy.
> 3. Every remediation that changes a live system (new detection, baseline change, credential policy)
>    goes through normal change control and validation — see the linked playbooks.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The process below follows **NIST SP 800-61r2 §3.4 (Post-Incident Activity)** and the **SANS PICERL
    "Lessons Learned" phase** cited at the foot of this page, but has **not** been exercised end to end
    for this page. Metrics definitions (MTTD/MTTR) and retention/notification obligations vary by
    organization and jurisdiction — confirm yours before reporting or acting. Remove this block when
    `verified: true`.

This is the **final phase of the incident-response lifecycle** and the one that makes the whole program
improve: Preparation → Detection & Analysis → Containment → Eradication & Recovery → **Post-Incident
Activity**. It turns a closed incident into better detection and a harder estate. It follows
[Eradication and Recovery](eradication-and-recovery.md).

**Trigger:** eradication and recovery are complete and recovered assets are stable in production.

**Goal:** capture what happened and why, measure the response, track every remediation to closure, and
feed concrete improvements back into Detection Engineering and Hardening so the next occurrence is
caught earlier or prevented.

## 1. Hold the after-action review (lessons-learned meeting)

Run a **blameless** review while memory is fresh — typically within one to two weeks of closure. Include
responders, asset/service owners and management. Answer the NIST questions: what happened and when; how
well did staff and process perform; what was needed that was missing; what would we do differently.

## 2. Build the incident timeline and root cause

Assemble one authoritative timeline from the containment, forensic and investigation evidence: initial
access → execution → persistence → impact → detection → containment → recovery. Drive to **root cause**
(e.g. 5-Whys), not just the proximate symptom.

→ [Windows Disk Artifacts](../forensics/windows-disk-artifacts.md) · [Live Memory Acquisition](../forensics/memory-acquisition-analysis.md) · [Network and PCAP Forensics](../forensics/network-pcap-forensics.md) · [Account Compromise Investigation](account-compromise.md)

## 3. Measure the response (MTTD / MTTR and dwell time)

Record the response metrics so the program can be judged over time:

| Metric | Meaning |
| --- | --- |
| Dwell time | Initial compromise → first detection |
| MTTD | Mean time to **detect** (alert/triage start) |
| MTTR | Mean time to **respond / recover** (contain + eradicate + restore) |
| Containment time | Detection → confirmed containment |

→ [Alert Tuning — Measuring Detection Efficacy (Metrics)](../detection-engineering/alert-tuning-false-positive-management.md#4-measuring-detection-efficacy-metrics)

## 4. Track remediation to closure

Convert every finding and "what was missing" into a tracked remediation item with an **owner**, a **due
date** and a **verification step**. The incident is not truly closed until these are closed and checked —
not when the host is back online.

## 5. Feed the lessons into Detection Engineering

For each attacker TTP that was missed or detected late, create or tune a detection so the same activity
alerts immediately next time, and validate it against the recorded behaviour.

→ [Detection Development Lifecycle](../detection-engineering/detection-development-lifecycle.md#5-deployment-continuous-review-protocol) · [Alert Tuning and False Positive Management](../detection-engineering/alert-tuning-false-positive-management.md)

## 6. Feed the lessons into Hardening and Preparation

Close the finding **class**, not just this instance: update the hardening baseline, credential policy
and the IR runbooks/plan so the gap this incident exposed cannot recur. This completes the loop back to
the Preparation phase.

→ [Hardening](../hardening/index.md) · [Credential Rotation After a Compromise](credential-rotation-after-compromise.md) · [Eradication and Recovery](eradication-and-recovery.md)

## 7. Retention, reporting and notification

Retain the evidence and incident record per policy and any legal hold, track required regulatory or
contractual notifications, and distribute the final report to the agreed stakeholders on a need-to-know
basis.

## 8. Close the incident

- Timeline and root cause are documented and agreed.
- Response metrics are recorded.
- Every remediation item has an owner and is tracked to closure.
- Detection and hardening improvements are deployed and validated.
- Evidence is retained and required notifications are complete.

When these hold, close the incident — the lifecycle returns to **Preparation**, now stronger.

## Related

- [Eradication and Recovery](eradication-and-recovery.md)
- [Automated Multi-Vector Containment](automated-containment.md)
- [Detection Development Lifecycle](../detection-engineering/detection-development-lifecycle.md)
- [Alert Tuning and False Positive Management](../detection-engineering/alert-tuning-false-positive-management.md)
- [Hardening](../hardening/index.md)

## External Resources & White Papers

- [NIST SP 800-61r2 — Computer Security Incident Handling Guide (§3.4 Post-Incident Activity)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS — Incident Handler's Handbook (PICERL — Lessons Learned)](https://www.sans.org/white-papers/33901/)
- [CISA — Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks)
