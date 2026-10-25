---
title: Run an Authorized Phishing Simulation — Measure Human and Technical Susceptibility
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-24
last_updated: 2026-10-24
tags: [phishing, phishing-simulation, social-engineering, spear-phishing, pretext, gophish, awareness-assessment, credential-harvesting-simulation, click-rate, report-rate, vishing, smishing, pretexting, spf, dkim, dmarc, sender-spoofing, initial-access, payload-free, authorized-testing, parrot-os, kali]
aliases: [phishing simulation, phishing assessment, run a phishing campaign, social engineering assessment, gophish campaign, measure click rate, phishing test, awareness test, spear phishing simulation, authorized phishing, pretext development, vishing, smishing, email spoofing test, dmarc gap test]
difficulty: intermediate
verified: false
---

# Run an Authorized Phishing Simulation — Measure Human and Technical Susceptibility
> **Created**: 2026-10-24T00:00:00Z
> **Last Modified**: 2026-10-24T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — PEOPLE ARE THE TARGET, SO THE RULES ARE STRICTER**
> A phishing simulation deceives real employees and collects evidence about their behaviour. Treat it
> with more care than any scan, not less.
> 1. **Written authorization and a defined audience.** Run only against an organization and recipient
>    list named in a signed engagement. Confirm who may be targeted (never customers, never a single
>    employee you could single out for punishment) and who the **named approver and escalation contact**
>    are before the first email leaves.
> 2. **Do not harvest real secrets.** The goal is a *susceptibility metric*, not a credential store.
>    Record that a user **submitted** on the landing page; do **not** store the password they typed
>    (§3). Redirect every submission to a short **teachable-moment** page. Anything incidentally
>    collected is sensitive personal data — minimise, encrypt, and destroy it on the schedule in the
>    engagement, under [Cyber Law](../fundamentals/concepts/cyber-law.md).
> 3. **No weaponized payloads.** This page runs a **payload-free** credential-awareness simulation — a
>    link to a controlled landing page. Malware, macro documents, and implant delivery are **out of
>    scope** and documented for awareness and defence only (§5), never as tooling.
> 4. **This is an assessment of a system, not a trap for a person.** Report aggregate rates and control
>    gaps; name systemic failures (no DMARC, no reporting button), not individuals. See
>    [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (GoPhish on Parrot OS / Kali) but have not
    been lab-run for this page. Flags, config-file keys and the capture toggles vary by version — confirm
    each against the tool's own docs and your engagement's rules of engagement before you send. Remove
    this block when `verified: true`.

**Trigger:** an authorized engagement has reached **Stage 2 (Initial Access)** and the scope includes a
**human-factor assessment** — you need to measure how many recipients click a lure, how many submit
credentials, how many **report** it, and whether the organization's inbound email controls (SPF / DKIM /
DMARC, anti-phishing policy) would stop a real spoof.

**Goal:** produce an evidenced verdict on phishing susceptibility — a click rate, a submit rate, a report
rate, and a list of **technical control gaps** — without harvesting real credentials and without
delivering any malicious payload. This page is part of Stage 2 (Initial Access) of the
[red-team lifecycle](index.md); its pretext and target list come from
[OSINT & Active Reconnaissance](osint-active-recon.md), and a captured *foothold* (in a real intrusion)
would hand off to [Foothold, Command-and-Control & Defense Evasion](foothold-command-control.md), which is
awareness-only here. For the theory of lures, pretexts and human bias, see
[Social Engineering](../fundamentals/concepts/social-engineering.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Scope & rules of engagement (§0) | engagement docs | Who may be targeted, the approver, the data-handling and abort rules |
| Pretext & target list (§1) | OSINT output | A believable, in-scope pretext and a recipient list with no outsiders |
| Sender & infra setup (§2) | domain, DNS, `gophish` | Whether a spoof *lands* — which is itself a finding about the target's filtering |
| Build the campaign (§3) | `gophish` | A payload-free lure, a credential-**awareness** landing page (no password storage), a training redirect |
| Launch, track, measure (§4) | `gophish` dashboard | Click / submit / report rates — the human-susceptibility metrics |
| *Payload delivery (know-it only)* (§5) | *theory — no tooling* | *How real phishing weaponizes the click — documented for detect/harden, not run here* |

## 0. Set the scope and rules of engagement once

Before anything technical, pin down — in writing — what a simulation must have and a scan does not:

```bash
# Fill from the signed engagement. These are guardrails, not suggestions.
CLIENT="example.com"                       # the authorized organization
AUDIENCE="./recipients_in_scope.csv"       # approved targets ONLY (First,Last,Email,Position)
APPROVER="ciso@example.com"                # named sign-off + escalation contact
WINDOW="2026-11-03 09:00 .. 2026-11-07 17:00"   # the agreed send window / business hours
ABORT_RULE="stop on any report to a customer, press, or regulator; notify approver within 15 min"
RETENTION="destroy all campaign data 30 days after the final report"
```

Confirm the audience contains **no customers, partners, or members of the public**, that there is a
**safe-word / abort channel** to the approver, and that HR/legal are aware if local law requires employee
notice. A phishing simulation without these is not authorized testing — it is just phishing.

## 1. Build a pretext from reconnaissance *(not from imagination)*

A believable lure is built from what the organization actually exposes. Pull the pretext material from the
recon you already did — do not invent a scenario that references systems the target doesn't use:

→ [OSINT & Active Reconnaissance](osint-active-recon.md) — harvested names, email format, job titles,
public tooling and vendor relationships that make a lure plausible (a "DocuSign" lure only lands where
DocuSign is used).

Pick a pretext that is **plausible but low-harm**: an internal IT notice, a benefits-enrolment reminder, a
shared-document notification. Avoid themes that cause real distress (bonuses, layoffs, bereavement) — they
inflate click rates dishonestly and damage trust. Keep the recipient list exactly as approved in §0; never
widen it because a target "looks interesting."

## 2. Stand up the sender and infrastructure

Use a dedicated simulation host and a look-alike (or engagement-provided) sending domain. Installing and
running GoPhish — the standard open-source authorized-phishing framework — gives you a sending engine, a
landing-page host, and a tracking dashboard:

```bash
# On the engagement host (Parrot/Kali or a scoped cloud VM). Use a release build, verify its checksum.
mkdir -p ~/phishsim && cd ~/phishsim
# Download the pinned GoPhish release for your platform, verify the SHA256, then unzip into THIS dir.
unzip gophish-*-linux-64bit.zip -d gophish && cd gophish

# Bind the admin UI to localhost only; expose ONLY the phishing listener publicly (edit config.json):
#   "admin_server": { "listen_url": "127.0.0.1:3333" }      # never expose the admin UI to the internet
#   "phish_server": { "listen_url": "0.0.0.0:80" }          # the landing-page listener
./gophish        # prints the one-time admin password on first run — change it immediately
```

Sending from a domain you control **also tests the target's inbound defences**. If your spoofed or
look-alike mail reaches the inbox, that is a finding in its own right:

```bash
# Check the TARGET's published policy — a weak/absent DMARC policy means spoofs land (a reportable gap).
dig +short TXT _dmarc."$CLIENT"            # look for p=reject / p=quarantine vs p=none / missing
dig +short TXT "$CLIENT" | grep -i spf     # SPF present? -all (hard fail) vs ~all (soft) vs none
```

A `p=none` or missing DMARC record is the single highest-value *technical* finding this engagement can
produce — note it now and tie it to the hardening page in [Harden it](#harden-it).

## 3. Build the campaign — payload-free, no password storage

In the GoPhish UI (over the localhost admin port) assemble four objects. The discipline that keeps this a
simulation and not a breach lives here:

- **Sending Profile** — the SMTP relay / sending domain from §2.
- **Email Template** — the pretext from §1, with a single tracked link. **No attachment, no macro, no
  executable.** Include the GoPhish open-tracking pixel if the engagement allows open-rate metrics.
- **Landing Page** — a look-alike logon page that records the **submission event** but is configured to
  **not capture the password value**. The teachable-moment redirect fires on submit:
    - *Capture Submitted Data*: **on** (you need the submit event for the metric).
    - *Capture Passwords*: **off** — you are measuring behaviour, not collecting secrets (§CAUTION #2).
    - *Redirect to*: a short internal **awareness page** ("This was an authorized test — here's how to
      spot it"), so every victim gets immediate training instead of a dead end.
- **Users & Groups** — import the approved `recipients_in_scope.csv` from §0 **only**.

```bash
# If you script the import instead of using the UI, keep the CSV to the approved columns and rows only:
head -1 "$AUDIENCE"      # First Name,Last Name,Email,Position  — and NOTHING outside the approved list
```

The result is a lure that proves whether a person *would* have handed over a credential, without you ever
holding that credential.

## 4. Launch, track, and measure

Schedule the campaign inside the agreed §0 window and watch the dashboard. The numbers that matter are
**rates, not names**:

| Metric | What it measures | Why it matters |
| :--- | :--- | :--- |
| **Open rate** | Lure reached the inbox and was read | Confirms deliverability (and the §2 filtering gap) |
| **Click rate** | Recipients who followed the link | Core human-susceptibility signal |
| **Submit rate** | Recipients who entered data on the landing page | The "would have been credential theft" figure |
| **Report rate** | Recipients who reported the mail to security | The organization's **immune response** — often the best metric |

A high **report rate** is a healthier result than a low click rate: it means the phishing-report workflow
works and people use it. If reports do not reach the SOC, that is a process finding. Keep the raw per-user
data in the encrypted evidence store only as long as §0's retention allows; everything in the report is
aggregate.

## 5. Payload delivery and post-click exploitation — *know it, detect it, harden it (not run here)*

In a real intrusion the click in §4 is followed by **payload delivery** — a macro-enabled document, an
ISO/LNK, an OAuth-consent grant, or an MFA-fatigue push — that turns a lure into code execution or a
session token. This project is **assessment-only and payload-free**, so **no delivery tooling or
procedure is published here.** Understand it only to detect and harden against it:

- **Know it:** [Foothold, Command-and-Control & Defense Evasion](foothold-command-control.md) covers how a
  payload persists and calls home — awareness-only. [Social Engineering](../fundamentals/concepts/social-engineering.md)
  covers vishing, smishing and pretexting as the non-email vectors of the same assessment.
- **It hands off from this page:** a real captured credential or token is the Stage 2 result that feeds
  host and directory enumeration — which is exactly why the controls in [Harden it](#harden-it) (phishing-
  resistant MFA, DMARC, ASR) matter even after a user clicks.

The takeaway for the assessment: a click/submit rate and a DMARC gap (§2) are reportable findings on their
own — you do **not** need to deliver a payload or steal a live credential to prove the organization is
phishable.

## Detect it

The lure itself is caught **upstream** at the mail gateway (SPF/DKIM/DMARC, anti-phishing policies — see
[Harden it](#harden-it)); what the [Detection](../detection/index.md) tab catches is the **post-click
result** — the anomalous sign-in or token use that a successful phish produces. Pair each with its hunt:

| Offensive outcome here | Detect it with |
| :--- | :--- |
| Harvested credential replayed — anomalous/impossible-travel sign-in, new device (§4 submit) | [KQL — Logon and Identity Hunting](../detection/kql/logon-identity.md) · [Sigma — Cloud Identity and Entra ID Attacks](../detection/sigma/cloud-identity-rules.md) |
| MFA-fatigue / consent-grant follow-on after the click (§5) | [Sigma — Cloud Identity and Entra ID Attacks](../detection/sigma/cloud-identity-rules.md) · [Hunting Cloud Identity Persistence in Entra ID and M365](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) |
| Credential reuse / spray with the phished password | [Splunk — Brute Force Success Correlation](../detection/spl/brute-force.md) · [KQL — Credential Access](../detection/kql/credential-access.md) |

The **report rate** (§4) is itself a detection signal — a working user-report button is the earliest
warning a real campaign gives the SOC.

## Harden it

Every finding on this page maps to a control:

- **Stop the spoof from landing** — publish and enforce SPF, DKIM and a `p=reject` DMARC policy, plus
  anti-phishing/anti-spoof rules on the mail platform:
  [Email Authentication Deployment (SPF, DKIM & DMARC)](../tasks/administration/email-authentication-deployment.md).
  This directly closes the §2 gap.
- **Make a submitted credential useless** — phishing-resistant MFA (FIDO2 / Windows Hello), Conditional
  Access and number-matching defeat credential replay and MFA fatigue:
  [Authentication, MFA, SSO and Federation](../fundamentals/concepts/authentication-mfa-sso.md) ·
  [Azure & Entra ID Security Baseline](../tasks/hardening/cloud-azure-security-baseline.md).
- **Neutralise a delivered payload** — block Office child processes and macro abuse at the endpoint:
  [Windows CIS — Attack Surface Reduction (ASR) & Credential Guard](../tasks/hardening/windows-cis-attack-surface-reduction.md).
- **Rehearse the response** — a reported or successful phish is an incident; drill the playbook:
  [Account Compromise Investigation](../tasks/incident-response/account-compromise.md).

## Notes

- **Metric, not a secret store.** Capture the *submit event*, not the password; redirect to training
  (§3). A simulation that hoards live credentials has created the very risk it was testing.
- **Report aggregates, blame systems.** Name the missing DMARC and the broken report workflow, never an
  individual employee — a phishing test used for punishment destroys the reporting culture you need.
- **A landed spoof is a finding before anyone clicks.** The §2 DNS check often yields the highest-value
  technical result on its own.
- **Stay in the window and the audience.** Send only inside §0's time window and recipient list; honour
  the abort rule the instant a mail reaches an outsider.
- Install notes: GoPhish is a single Go binary (release zip for Parrot/Kali or a scoped VM); bind the
  admin UI to `127.0.0.1` and expose only the phishing listener.

## Related

- [Offensive — Overview](index.md) — this is part of Stage 2 (Initial Access)
- [OSINT & Active Reconnaissance](osint-active-recon.md) — where the pretext and target list come from · [Web Application Assessment](web-application-assessment.md) — a credential-harvest landing page is a web app
- [Foothold, Command-and-Control & Defense Evasion](foothold-command-control.md) — where a real captured foothold would go next (awareness-only)
- Reference: [Social Engineering](../fundamentals/concepts/social-engineering.md) · [OSINT and Reconnaissance](../fundamentals/concepts/osint.md) · [Authentication, MFA, SSO and Federation](../fundamentals/concepts/authentication-mfa-sso.md) · [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md)
- Defensive counterparts: [Email Authentication Deployment (SPF, DKIM & DMARC)](../tasks/administration/email-authentication-deployment.md) · [Azure & Entra ID Security Baseline](../tasks/hardening/cloud-azure-security-baseline.md) · [Windows CIS — Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Account Compromise Investigation](../tasks/incident-response/account-compromise.md)

## External Resources & White Papers

- [GoPhish — open-source phishing framework](https://getgophish.com/) · [GoPhish documentation](https://docs.getgophish.com/) — the toolkit this page uses
- [MITRE ATT&CK — Phishing (T1566)](https://attack.mitre.org/techniques/T1566/) — the technique and its sub-techniques this simulation models
- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) — handling a phish that succeeds
- [CISA — Teach Employees to Avoid Phishing](https://www.cisa.gov/) · [M3AAWG Email Authentication best practices](https://www.m3aawg.org/) — the DMARC/SPF/DKIM guidance behind the hardening
