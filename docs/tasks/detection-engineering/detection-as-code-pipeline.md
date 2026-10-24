---
title: Detection-as-Code Pipeline (Version Control, CI Validation & Staged Deploy)
type: workflow
platforms:
  - Microsoft Defender
  - Splunk
  - SentinelOne
  - GitHub
  - Linux
languages:
  - Sigma
  - KQL
  - SPL
  - S1QL
  - Python
  - Bash
tasks:
  - Detection Engineering
  - Automation
  - Assurance
verified: false
difficulty: intermediate
tags:
  - detection-engineering
  - detection-as-code
  - ci-cd
  - version-control
  - sigma
  - pysigma
  - github-actions
  - promotion
aliases:
  - detection as code
  - DaC pipeline
  - detection CI/CD
  - detection rule pipeline
---

# Detection-as-Code Pipeline (Version Control, CI Validation & Staged Deploy)
> **Created**: 2026-10-24T00:00:00Z
> **Last Modified**: 2026-10-24T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This workflow contains pipeline, Git and deployment commands. Before running any action:
> 1. Ensure you are operating against a `Test`/`Dev` detection workspace, not production SIEM/EDR.
> 2. Validate deploy steps with a dry-run / `--whatif` equivalent and a canary scope before a fleet-wide push.
> 3. Never commit SIEM API tokens, deploy keys or tenant IDs — use the CI secret store.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`. The pipeline shapes, CI gates and promotion
    model below are doc-checked against Sigma, pySigma, GitHub Actions and MITRE ATT&CK
    documentation; wire them to your own backends and run them in a lab workspace before
    trusting them in production.

**Trigger:** you have more than a handful of detections and need them reviewed, validated and shipped the same way as application code — not hand-edited in a SIEM console.

**Goal:** every detection change is version-controlled, peer-reviewed, automatically validated in CI, and promoted through `dev → test → prod` with a clean rollback path and a full audit trail.

This page is the **deploy-and-govern** half of the [Detection Development Lifecycle](detection-development-lifecycle.md) (DDLC stage 6). The DDLC covers *how you author and tune* a rule; this page covers *how a rule safely gets from a pull request into production and back out again*.

<!-- Rules: every step links to an entry/workflow instead of repeating its content.
     Inline a command only when it is specific to the pipeline. Keep steps short. -->

---

## 1. Pipeline overview

Detection-as-Code (DaC) treats detections as source artifacts in Git. A change flows left-to-right; each gate must pass before the next stage runs.

```text
[ Author edits rule ]
        │  git branch + commit (signed)
        ▼
[ Pull Request ]───────────────► peer review + CODEOWNERS sign-off
        │
        ▼
[ CI: VALIDATE ]  lint schema · sigma check · unique IDs · ATT&CK tags · pytest
        │ (all green)
        ▼
[ CI: BUILD ]     convert Sigma → SPL / KQL / S1QL (backend compile only)
        │
        ▼
[ CI: TEST ]      unit tests + sample-log fire/no-fire fixtures (no prod data)
        │
        ▼
[ DEPLOY: dev ]   auto-push to a dev detection workspace
        │  canary bake + baseline review
        ▼
[ PROMOTE: test ] manual approval → test workspace
        │  false-positive baseline (see Alert Tuning)
        ▼
[ PROMOTE: prod ] manual approval + change ticket → production SIEM/EDR
        │
        ▼
[ Rollback ]      git revert <sha> → pipeline re-deploys the previous state
```

The source of truth is the **Git repository**, never the SIEM console. A rule that exists only in the console is drift (see §6).

---

## 2. Version control: repository layout & rule metadata

Keep platform-neutral [Sigma](../../detection/sigma/index.md) rules as the authoring format and let the pipeline compile them to each backend. This keeps one reviewable artifact per detection instead of three hand-maintained query dialects.

```text
detections/
├── rules/                     # Sigma source of truth (one rule per file)
│   ├── credential-access/
│   │   └── lsass-handle-access.yml
│   └── execution/
│       └── suspicious-powershell-encodedcommand.yml
├── tests/                     # fire / no-fire sample-log fixtures per rule
│   └── credential-access/
│       └── lsass-handle-access_test.yml
├── config/                    # pySigma backend + field-mapping pipelines
│   ├── defender.yml
│   ├── splunk.yml
│   └── sentinelone.yml
└── .github/workflows/detections.yml
```

Each rule carries the metadata the pipeline and audit depend on. `status` is the promotion state; `id` must be a stable UUID (never reuse one); `tags` carry the ATT&CK technique so coverage can be measured.

```yaml
title: LSASS Handle Access by Unexpected Process
id: 4a9f2b3e-781c-4b92-91ef-8f4316d8a012
status: test                       # experimental -> test -> stable (promotion state)
description: Non-OS process opening a handle to lsass.exe with read access
author: Command & Code Detection Engineering
date: 2026-10-24
references:
  - https://attack.mitre.org/techniques/T1003/001/
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1438'
      - '0x1fffff'
  filter_os:
    SourceImage|endswith:
      - '\csrss.exe'
      - '\wininit.exe'
  condition: selection and not filter_os
falsepositives:
  - Backup and EDR agents that legitimately read process memory
level: high
```

Version-control discipline:

- **One rule per file, one logical change per commit** — small diffs are reviewable and revertable.
- **Immutable IDs** — the UUID is the rule's identity across every backend and every dashboard; renaming the file is fine, reusing or changing an `id` is not.
- **Signed commits + protected `main`** — require signed commits and PR review so detection logic has the same chain of custody as production code (Golden Standards §2.4).
- **`CODEOWNERS`** — route detection paths to the detection-engineering team for mandatory review.

---

## 3. CI: VALIDATE gate

The first CI job fails the PR fast on anything malformed, before any backend work. Run the Sigma validator, a schema/field check, and unit tests.

```bash
# Install the toolchain (pin versions in requirements.txt for reproducible CI)
python -m pip install sigma-cli pysigma-backend-splunk pysigma-backend-microsoft365defender

# 1. Structural + logic validation of every Sigma rule
sigma check detections/rules/

# 2. Fail on duplicate rule IDs (identity collisions break dashboards + promotion)
grep -rhoE '^id:\s*\S+' detections/rules/ | sort | uniq -d

# 3. Fail on rules missing an ATT&CK technique tag (coverage hygiene)
for rule in $(find detections/rules -name '*.yml'); do
    grep -qE 'attack\.t[0-9]{4}' "$rule" || echo "MISSING ATT&CK tag: $rule"
done

# 4. Project unit tests (metadata schema, naming, status values)
pytest detections/tests/ -q
```

Wire the same gates into [GitHub Actions](https://docs.github.com/actions) so they run on every pull request:

```yaml
name: detections-ci
on:
  pull_request:
    paths:
      - 'detections/**'
permissions:
  contents: read
jobs:
  validate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install toolchain
        run: python -m pip install -r detections/requirements.txt
      - name: Validate Sigma
        run: sigma check detections/rules/
      - name: Unit tests
        run: pytest detections/tests/ -q
```

Guard the pipeline against its own worst failure mode — a leaked SIEM/deploy token in a commit. Pair this gate with the [CI/CD Secret Leak detection](../../detection/sigma/cicd-secret-leak.md) and keep every credential in the CI secret store, never in the repo.

---

## 4. CI: BUILD — compile Sigma to each backend

The build job converts the validated Sigma rules into the query dialect of each target. This proves every rule compiles for every backend *before* deploy; the detailed per-backend mapping and tuning is its own workflow (a follow-up slice), so here the pipeline only compiles and stores the artifacts.

```bash
# Compile to each backend; a conversion error fails the build
sigma convert -t splunk   -p detections/config/splunk.yml       detections/rules/ -o build/splunk.conf
sigma convert -t microsoft365defender -p detections/config/defender.yml detections/rules/ -o build/defender.kql
# SentinelOne S1QL via its pySigma backend / pipeline
sigma convert -t sentinelone -p detections/config/sentinelone.yml detections/rules/ -o build/sentinelone.s1ql
```

Backends map to the site's query references: [KQL](../../detection/kql/index.md) for Microsoft Defender, [SPL](../../detection/spl/index.md) for Splunk, and [S1QL](../../detection/s1ql/index.md) for SentinelOne. Store `build/` as a CI artifact — it is the exact content that the deploy job ships, so it is also the diff you review at promotion.

---

## 5. CI: TEST — fire / no-fire fixtures

Validate detection *logic* against committed sample logs, never against production telemetry. Each rule gets a fixture with events that **must** fire and events that **must not**.

```yaml
# detections/tests/credential-access/lsass-handle-access_test.yml
rule: ../../rules/credential-access/lsass-handle-access.yml
should_fire:
  - TargetImage: 'C:\Windows\System32\lsass.exe'
    GrantedAccess: '0x1438'
    SourceImage: 'C:\Users\evil\dump.exe'
should_not_fire:
  - TargetImage: 'C:\Windows\System32\lsass.exe'
    GrantedAccess: '0x1438'
    SourceImage: 'C:\Windows\System32\wininit.exe'   # legitimate OS process
```

For end-to-end validation against *real* telemetry — running the technique and confirming the rule fires on live sensors — use adversary emulation in an authorized lab (Atomic Red Team), which is a separate follow-up slice and is already outlined in the [DDLC](detection-development-lifecycle.md#3-adversary-emulation-testing-atomic-red-team). Tie your test coverage to real adversary behaviour via the [Adversary Emulation & ATT&CK Profiling](../threat-intelligence/adversary-emulation-profiling.md) workflow.

---

## 6. Staged deploy & gated promotion

Promotion is driven by the rule's `status` field and by pipeline approvals — not by editing the console. Each environment is a separate detection workspace with its own credentials (least privilege; the prod deploy identity can write only prod).

| Stage | Trigger | Scope | Gate before next stage |
| :--- | :--- | :--- | :--- |
| **dev** | merge to `main` (auto) | dev workspace / synthetic data | Canary bake; no build/alert errors |
| **test** | manual approval | test workspace / mirrored subset | False-positive baseline (see [Alert Tuning](alert-tuning-false-positive-management.md)) ≤ threshold |
| **prod** | manual approval + change ticket | production SIEM/EDR, fleet-wide | Post-deploy health check; owner sign-off |

A deploy job reads the compiled artifact and pushes only the rules whose `status` qualifies for that environment:

```bash
# Deploy to a single environment; --canary limits an initial prod push to a pilot group
./scripts/deploy_detections.sh --env dev    --rules build/ --status experimental,test,stable
./scripts/deploy_detections.sh --env test   --rules build/ --status test,stable
./scripts/deploy_detections.sh --env prod   --rules build/ --status stable --canary pilot-hosts
```

**Rollback is a Git operation, not a console edit.** Because the repo is the source of truth, reverting the commit and re-running the pipeline restores the exact previous detection state:

```bash
git revert <bad-detection-sha>   # creates a new commit undoing the change
git push origin main             # pipeline re-deploys the previous, known-good state
```

Promote by bumping `status` in a normal reviewed PR (`experimental → test → stable`); the audit trail is the merge history.

---

## 7. Change management, drift & audit

- **Drift detection** — periodically export the live rules from each backend and diff them against the compiled artifact. Any rule in the console that is not in Git (or differs from it) is drift: re-import it into a PR or delete it. The console is never authoritative.
- **Traceability (Golden Standards §1 P11)** — every production detection maps to a merged, signed PR with a reviewer and a timestamp. No out-of-band edits.
- **Coverage reporting** — because every rule is tagged with its ATT&CK technique (§2), a CI step can roll the `attack.t####` tags into an ATT&CK Navigator layer for coverage/heatmap reporting — the dedicated coverage-mapping workflow is a follow-up slice; see the [MITRE ATT&CK Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) reference.
- **Least privilege** — CI deploy identities are per-environment and scoped to detection content only; store their tokens in the CI secret store and rotate them.

---

## Notes

- **Why Sigma as the source of truth:** one reviewable artifact compiles to every backend, so a logic review is done once rather than three times, and coverage is measured from a single tag set. If a backend needs a rule Sigma cannot express, keep it as a native query under the same layout and metadata so it is still version-controlled and promoted the same way.
- **`status` vocabulary:** Sigma defines `experimental`, `test`, `stable`, `deprecated`, `unsupported`. Map your environments to these rather than inventing new values, so `sigma check` stays happy.
- **Secrets:** a detection pipeline holds write access to your SIEM/EDR — treat its credentials and runners as production infrastructure.

## Related

- [Detection Development Lifecycle (DDLC) and Testing](detection-development-lifecycle.md) — how to author and tune the rule this pipeline ships.
- [Alert Tuning and False Positive Management](alert-tuning-false-positive-management.md) — the baseline gate before `test → prod` promotion.
- [Sigma Rules (index)](../../detection/sigma/index.md) · [Sigma Rule Examples](../../detection/sigma/examples.md) — the authoring format and worked rules.
- [Detection Rule — CI/CD Secret Leak](../../detection/sigma/cicd-secret-leak.md) — detect the pipeline's own worst failure: a leaked deploy token.
- [Cyber Threat Intelligence — Adversary Emulation & ATT&CK Profiling](../threat-intelligence/adversary-emulation-profiling.md) — source the behaviours your fire/no-fire tests should cover.
- [Security Information and Event Management (SIEM)](../../fundamentals/concepts/siem.md) — the platforms this pipeline deploys to.

## External Resources & White Papers

- [Sigma — Rule specification](https://sigmahq.io/docs/basics/rules.html)
- [Sigma — Meta & rule conversion (`sigma-cli`)](https://sigmahq.io/docs/guide/getting-started.html)
- [pySigma — backends & processing pipelines](https://sigmahq-pysigma.readthedocs.io/)
- [GitHub Actions — workflow syntax](https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
