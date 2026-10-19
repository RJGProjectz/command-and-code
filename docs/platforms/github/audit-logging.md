---
title: GitHub Audit Log & Security Log
platforms: [GitHub]
languages: [Bash]
tasks: [Investigation, Incident Response, Forensics, Hardening]
category: Logging
tags: [github, audit log, security log, audit log streaming, git events, hashed token, read:audit_log, enterprise cloud]
aliases: [gh api orgs audit-log, github org audit log search, github audit log by token, hashed_token search, github audit log retention, github audit log streaming splunk, github user security log, who deleted github repo, who disabled branch protection]
difficulty: intermediate
verified: true
last_verified: 2026-10-18
---

# GitHub Audit Log & Security Log

| Log | Covers | Where |
| :--- | :--- | :--- |
| **Organization audit log** | Org, repo, team, app, Actions, secret scanning, member events | *Org settings → Logs → Audit log*; REST on Enterprise Cloud |
| **Enterprise audit log** | All orgs in an enterprise plus enterprise settings | *Enterprise settings → Audit log*; streaming |
| **User security log** | Your own sign-ins, keys, tokens, OAuth grants | *Settings → Archives → Security log* |
| **Git events** | `git.clone`, `git.fetch`, `git.push` | Audit log with `include=git` or export; kept for **7 days** |

Web (non-Git) events are kept in the audit log for 180 days. Stream the log to your SIEM if you need more ([audit log streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise) to Splunk, Azure Event Hubs, Amazon S3, Google Cloud Storage, Azure Blob Storage or Datadog).

!!! warning "Before you run anything"
    Every command was checked against docs.github.com (2026-10-18); this guide does not run them against a live organization. The REST endpoint is available to organizations on **GitHub Enterprise Cloud**; it needs an org owner and a token with `read:audit_log`. On Free and Team plans, search and export from the web UI.

## 1. Query the org audit log

```bash
ORG=my-org
gh auth refresh --scopes read:audit_log
gh api "orgs/$ORG/audit-log?phrase=action:repo.destroy&per_page=100" --paginate \
  --jq '.[] | {at: (."@timestamp" / 1000 | todate), action, actor, repo, actor_ip}'

# Everything one actor did since a date (the phrase must be URL-encoded when it contains spaces)
gh api -X GET "orgs/$ORG/audit-log" -f phrase='actor:suspect-user created:>=2026-10-01' -f include=all -F per_page=100 --paginate \
  --jq '.[] | [(."@timestamp" / 1000 | todate), .action, .repo // "-"] | @tsv'
```

Parameters: `phrase` (search qualifiers), `include` = `web` (default) / `git` / `all`, `order` = `desc` / `asc`, `per_page` up to 100, cursors `after` / `before` from the `Link` header (`--paginate` follows them). `actor_ip` appears only when the org enables IP disclosure.

Useful qualifiers: `action:`, `actor:`, `repo:my-org/app`, `created:2026-10-01..2026-10-18`, `country:`, `operation:` (`access`, `authentication`, `create`, `modify`, `remove`, `restore`, `transfer`).

## 2. Events worth an alert

| Action | Why it matters |
| :--- | :--- |
| `org.update_member` | Member promoted to owner (or demoted) |
| `org.add_member`, `org.add_outside_collaborator`, `repo.add_member`, `team.add_member` | New access |
| `org.disable_two_factor_requirement` | 2FA requirement switched off |
| `repo.access` | Repository visibility changed (private → public is a data leak) |
| `repo.destroy`, `repo.transfer` | Repository deleted or transferred |
| `protected_branch.destroy`, `protected_branch.policy_override` | Branch protection removed or bypassed by an admin |
| `repository_ruleset.destroy`, `repository_ruleset.update` | Ruleset deleted or weakened |
| `public_key.create` | Deploy key added to a repo (or SSH key to a user) |
| `hook.create` | Webhook added: can ship every push to an outside URL |
| `integration_installation.create` | GitHub App installed |
| `personal_access_token.access_granted`, `personal_access_token.request_created` | Fine-grained PAT given org access |
| `secret_scanning_push_protection.bypass` | Someone pushed a detected secret anyway |
| `org.secret_scanning_push_protection_disable` | Push protection turned off |
| `org.register_self_hosted_runner` | New self-hosted runner: code runs on that host |
| `org.create_actions_secret`, `environment.create_actions_secret` | Secret created |
| `repo.set_default_workflow_permissions`, `repo.set_workflow_permission_can_approve_pr` | `GITHUB_TOKEN` widened |
| `workflows.approve_workflow_job` | Deployment approved (who approved production) |
| `git.clone` (many repos, one actor, short window) | Bulk clone / exfiltration |

## 3. Find what a leaked token did

The audit log records a `hashed_token` (Base64 SHA-256 of the token) for token-authenticated events. Hash the token without putting it in history, then search:

```bash
read -rs TOKEN                                                   # paste, then Enter; nothing is echoed
HASH=$(printf '%s' "$TOKEN" | openssl dgst -sha256 -binary | base64); unset TOKEN
gh api -X GET "orgs/$ORG/audit-log" -f phrase="hashed_token:\"$HASH\"" -F per_page=100 --paginate \
  --jq '.[] | [(."@timestamp" / 1000 | todate), .action, .actor, .repo // "-", .programmatic_access_type // "-"] | @tsv'
```

Web search and the REST API do not return Git events for this query; export the audit log (JSON/CSV, Git events included) to see `git.clone` / `git.push` by that token.

## 4. User security log

For a personal account (or to see what a compromised user's session did), review *Settings → Archives → Security log*: `oauth_authorization.create`, `personal_access_token.create`, `public_key.create`, `two_factor_authentication.disabled`, `user.change_password`. Export it as JSON for the case file.

## Related

- [Incident response](incident-response.md)
- [Persistence & hunting](persistence-hunting.md)
- [Azure activity log](../azure/audit-logging.md) · [AWS CloudTrail](../aws/audit-logging.md)

## Sources

- [Audit log events for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [REST: get the audit log for an organization](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization)
- [Identifying audit log events performed by an access token](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token)
- [Reviewing the audit log for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
