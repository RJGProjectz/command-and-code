---
title: GitHub Persistence & Threat Hunting
platforms: [GitHub]
languages: [Bash]
tasks: [Threat Hunting, Incident Response, Investigation, Detection Engineering]
category: Persistence
tags: [github, persistence, threat hunting, deploy keys, webhooks, github apps, self-hosted runners, workflow backdoor, outside collaborators, personal access tokens, mitre attack, supply chain]
aliases: [github persistence techniques, hunt github backdoor deploy key, github rogue webhook, malicious github app installation, self-hosted runner persistence, github workflow backdoor, github bulk clone exfiltration, github ruleset bypass actor]
difficulty: advanced
verified: true
last_verified: 2026-10-18
---

# GitHub Persistence & Threat Hunting

An attacker with a stolen GitHub token or session wants access that survives a password reset and token revocation: a key on a repo, a webhook that ships every push out, an app installation, a runner on their host, or a workflow change that leaks secrets on the next run. Hunt each one below, then confirm with the [audit log](audit-logging.md).

!!! warning "Before you run anything"
    Every command was checked against docs.github.com REST reference and the GitHub CLI manual (2026-10-18); this guide does not run them against a live organization. All hunts are read-only. Baseline your org first: legitimate integrations look exactly like these findings.

## 1. Techniques and where to look

| Technique | ATT&CK | Hunt | Audit action |
| :--- | :--- | :--- | :--- |
| Stolen token or session used as the user | T1078.004 | Token by hash, unusual `actor_ip` / country | [`hashed_token:`](audit-logging.md#3-find-what-a-leaked-token-did) |
| New PAT, SSH key or deploy key | T1098.001 | Deploy keys, user keys, PAT approvals | `public_key.create`, `personal_access_token.access_granted` |
| New member, owner or outside collaborator | T1136.003, T1098.003 | Owners, outside collaborators, team adds | `org.add_member`, `org.update_member`, `repo.add_member` |
| OAuth / GitHub App consent | T1528 | App installations, OAuth grants | `integration_installation.create`, `oauth_authorization.create` |
| Webhook to an outside URL | T1567 | Repo and org hooks | `hook.create` |
| Workflow or action backdoor | T1195.001 | Recent changes to `.github/workflows`, unpinned actions | `git.push`, `workflows.*` |
| Self-hosted runner on attacker host | T1078.004 | Runners, runner groups | `org.register_self_hosted_runner` |
| Secrets read from code or CI | T1552.001 | Secret scanning alerts, bypasses | `secret_scanning_push_protection.bypass` |
| Logging or protection turned off | T1685.002 | Ruleset/protection changes, streaming off | `protected_branch.destroy`, `repository_ruleset.destroy` |
| Bulk clone of code repositories | T1213.003 | `git.clone` volume per actor | `git.clone` (7-day retention) |

## 2. Keys, hooks, apps and runners across the org

```bash
ORG=my-org
for r in $(gh repo list "$ORG" --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner'); do
  # gh --jq has no --arg, so prefix each row with the repo name afterwards
  gh api "repos/$r/keys" --jq '.[] | ["deploy-key", .title, (if .read_only then "ro" else "RW" end), .created_at, (.last_used // "-")] | @tsv' | sed "s|^|$r\t|"
  gh api "repos/$r/hooks" --jq '.[] | ["webhook", .config.url, (.events | join(",")), .active, .created_at] | @tsv' 2>/dev/null | sed "s|^|$r\t|"
  gh api "repos/$r/actions/runners" --jq '.runners[] | ["runner", .name, .os, .status, ([.labels[].name] | join(","))] | @tsv' 2>/dev/null | sed "s|^|$r\t|"
done
gh api "orgs/$ORG/hooks" --jq '.[] | ["org", "webhook", .config.url, (.events | join(",")), .active, .created_at] | @tsv'
gh api "orgs/$ORG/actions/runners" --paginate --jq '.runners[] | ["org", "runner", .name, .os, .status] | @tsv'
gh api "orgs/$ORG/installations" --jq '.installations[] | ["org", "app", .app_slug, .repository_selection, .created_at] | @tsv'
```

Questions: does every webhook URL belong to a known service; is every write deploy key needed; does every runner name match your fleet; was any app installed with `repository_selection: all` in the incident window?

## 3. Workflow backdoors

```bash
REPO=my-org/app
gh api "repos/$REPO/commits?path=.github/workflows&since=2026-10-01T00:00:00Z" --jq '.[] | [.sha[0:12], .commit.author.date, .author.login // .commit.author.name, .commit.message | split("\n")[0]] | @tsv'
git log --since=2026-10-01 --format='%h %ad %an %G? %s' --date=iso -- .github/workflows .github/actions
git grep -nE 'uses: [^@]+@(main|master|v[0-9]+)$' -- .github/workflows        # unpinned actions
git grep -nE 'pull_request_target|workflow_run' -- .github/workflows
git grep -nE '\$\{\{ *github\.event\.(issue|pull_request|comment|review|head_commit)\.' -- .github/workflows   # injection sinks
git grep -nE 'curl|wget|base64 -d|toJSON\(secrets\)' -- .github/workflows
```

`%G?` shows the signature status (`G` good, `N` none): an unsigned workflow change in a repo that requires signing is a lead. `toJSON(secrets)` dumps every secret the job can see.

## 4. People and tokens

```bash
gh api "orgs/$ORG/members?role=admin" --jq '.[].login'
gh api "orgs/$ORG/outside_collaborators" --paginate --jq '.[].login'
gh api -X GET "orgs/$ORG/audit-log" -f phrase='action:org.update_member created:>=2026-10-01' --jq '.[] | [(."@timestamp"/1000|todate), .actor, .user // "-"] | @tsv'
gh api -X GET "orgs/$ORG/audit-log" -f phrase='action:public_key.create created:>=2026-10-01' --jq '.[] | [(."@timestamp"/1000|todate), .actor, .repo // .user // "-"] | @tsv'
```

Compare each result with tickets or change records. Removal steps are in [Incident response](incident-response.md#2-contain-a-compromised-account-or-org).

## Related

- [Audit log](audit-logging.md)
- [Identity & access](identity-access.md)
- [Hypothesis-driven hunting framework](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md)
- [AWS persistence & hunting](../aws/persistence-hunting.md)

## Sources

- [MITRE ATT&CK SaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/saas/)
- [REST: deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys) · [repository webhooks](https://docs.github.com/en/rest/repos/webhooks) · [self-hosted runners](https://docs.github.com/en/rest/actions/self-hosted-runners)
- [Secure use reference (Actions)](https://docs.github.com/en/actions/reference/security/secure-use)
- [git log pretty formats (`%G?`)](https://git-scm.com/docs/pretty-formats)
