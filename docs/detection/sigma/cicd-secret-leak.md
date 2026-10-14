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
verified: true
last_verified: 2026-10-13
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

!!! warning "Before you deploy"
    Action names were checked (2026-10-13) against GitHub's organization audit log event reference, and the gitleaks
    message against its source. GitHub audit events reach a SIEM only through audit log streaming (Enterprise) or an
    API poller. Organization events carry an `org.` prefix in some exports, so the rules match with `contains`.

- **ATT&CK**: [T1552.001 — Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/), [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) (formerly T1562.001)
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
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: github
  service: audit
detection:
  selection:
    action|contains:
      - 'secret_scanning.disable'
      - 'secret_scanning_new_repos.disable'
      - 'secret_scanning_push_protection_disable'
      - 'secret_scanning_push_protection_new_repos_disable'
      - 'secret_scanning_push_protection.disable'
  condition: selection
falsepositives:
  - Repository archival or migration by administrators
level: high
```

## SPL — GitHub audit stream and gitleaks in CI

```spl
index=github (action="*secret_scanning_push_protection.bypass*" OR action="*secret_scanning.disable*"
    OR action="*secret_scanning_new_repos.disable*" OR action="*secret_scanning_push_protection_disable*"
    OR action="*secret_scanning_push_protection_new_repos_disable*" OR action="*secret_scanning_push_protection.disable*")
| eval signal=if(like(action, "%bypass%"), "push protection bypass", "secret scanning disabled")
| table _time, signal, actor, repo, org, action
```

gitleaks exits non-zero and logs `leaks found: N` (a warning-level line) when it finds a secret; ship CI job logs to the SIEM and alert on it:

```spl
index=cicd "leaks found:"
| rex "leaks found: (?<leak_count>\d+)"
| where leak_count > 0
| stats sum(leak_count) as leaks values(job_name) as jobs by repo, branch
```

## KQL (Microsoft Sentinel, custom GitHub table)

```kql
GitHubAuditLogPolling_CL
| where action_s has_any ("secret_scanning_push_protection.bypass", "secret_scanning.disable",
    "secret_scanning_new_repos.disable", "secret_scanning_push_protection_disable",
    "secret_scanning_push_protection_new_repos_disable", "secret_scanning_push_protection.disable")
| project TimeGenerated, action_s, actor_s, repo_s, org_s
```

Table and column names depend on the connector; adjust to yours.

## Triage

1. A real secret in Git history is compromised: **rotate it first**, then clean history.
2. Check the provider's logs (cloud, SaaS) for use of the secret since the push time.
3. Ask why the bypass was chosen; "I'll fix it later" with no fix is the finding.

## Test it

Atomic Red Team has no test that produces GitHub audit events ([T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md)
*Find and Access Github Credentials* covers the endpoint side). In a throwaway repository you own:

1. Turn push protection on, push a commit containing a token you created for the test and revoke straight after,
   and choose a bypass reason: one `secret_scanning_push_protection.bypass` event.
2. Turn secret scanning off for that repository: one `repository_secret_scanning.disable` event (matched by
   `secret_scanning.disable`).
3. Run `gitleaks git .` in a CI job on a branch with a fake key in a test file: the job log shows `leaks found: 1`.

## Sources

- [GitHub Docs — Audit log events for your organization](https://docs.github.com/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [GitHub Docs — Push protection](https://docs.github.com/code-security/secret-scanning/protecting-pushes-with-secret-scanning)
- [gitleaks (source of the `leaks found` message)](https://github.com/gitleaks/gitleaks)
