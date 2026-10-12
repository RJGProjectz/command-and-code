---
title: Detection Rule — CI/CD Secret Leak
type: entry
platforms:
  - Splunk
languages:
  - Sigma
  - SPL
  - KQL
tasks:
  - Detection Engineering
  - Incident Response
verified: false
difficulty: intermediate
tags:
  - github
  - secret-scanning
  - push-protection
  - gitleaks
  - devsecops
  - t1552.001
---

# Detection Rule — CI/CD Secret Leak

Detects secrets reaching a repository: a developer bypassing GitHub push protection, someone turning secret scanning
off, and a pipeline secret scanner (gitleaks) finding a credential.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    GitHub audit events reach a SIEM only through audit log streaming (Enterprise) or an API poller. Action names
    come from the GitHub audit log; check the current names in your stream before relying on exact matches.
    The `contains` matches below are deliberately loose.

- **ATT&CK**: [T1552.001 — Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/), [T1562.001 — Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- **Concept**: [Secure SDLC & DevSecOps](../../fundamentals/concepts/secure-sdlc-devsecops.md)

## Sigma rule — push protection bypass

```yaml
title: GitHub Secret Push Protection Bypassed
id: 4d706228-88ee-40f3-aaec-d2a75182e62f
status: experimental
description: Detects a user pushing a detected secret by bypassing GitHub push protection.
references:
  - https://docs.github.com/en/code-security/secret-scanning/protecting-pushes-with-secret-scanning
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.credential-access
  - attack.t1552.001
logsource:
  product: github
  service: audit
detection:
  selection:
    action|contains: 'secret_scanning_push_protection.bypass'
  condition: selection
falsepositives:
  - Test fixtures and documented example keys (the bypass reason says "used in tests" or "false positive")
level: medium
```

## Sigma rule — secret scanning disabled

```yaml
title: GitHub Secret Scanning Disabled
id: 42be038b-bd9d-4546-8fd6-574dec0fefdf
status: experimental
description: Detects secret scanning or push protection being turned off for a repository, organisation or enterprise.
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.defense-evasion
  - attack.t1562.001
logsource:
  product: github
  service: audit
detection:
  selection:
    action|contains|all:
      - 'secret_scanning'
      - 'disable'
  condition: selection
falsepositives:
  - Repository archival or migration by administrators
level: high
```

## SPL — GitHub audit stream and gitleaks in CI

```spl
index=github (action="*secret_scanning_push_protection.bypass*" OR (action="*secret_scanning*" action="*disable*"))
| eval signal=if(like(action, "%bypass%"), "push protection bypass", "secret scanning disabled")
| table _time, signal, actor, repo, org, action
```

gitleaks exits non-zero and prints `leaks found: N` when it finds a secret; ship CI job logs to the SIEM and alert on it:

```spl
index=cicd "leaks found:"
| rex "leaks found: (?<leak_count>\d+)"
| where leak_count > 0
| stats sum(leak_count) as leaks values(job_name) as jobs by repo, branch
```

## KQL (Microsoft Sentinel, custom GitHub table)

```kql
GitHubAuditLogPolling_CL
| where action_s has "secret_scanning_push_protection.bypass"
    or (action_s has "secret_scanning" and action_s has "disable")
| project TimeGenerated, action_s, actor_s, repo_s, org_s
```

Table and column names depend on the connector; adjust to yours.

## Triage

1. A real secret in Git history is compromised: **rotate it first**, then clean history.
2. Check the provider's logs (cloud, SaaS) for use of the secret since the push time.
3. Ask why the bypass was chosen; "I'll fix it later" with no fix is the finding.
