---
title: GitHub
type: index
---

# GitHub

GitHub organizations and repositories: tokens and keys, org and team access, Actions secrets and OIDC, rulesets, Dependabot, secret and code scanning, the audit log, and day-to-day `git` work.

!!! info "Tools"
    Use **GitHub CLI** (`gh`) for the API (`gh api` covers any REST endpoint, with `--paginate` and `--jq`) and **git** for repository history. Org-wide reads need an org owner; the audit log REST API needs GitHub Enterprise Cloud and `read:audit_log`.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Find out which account and token `gh` or `git` is using | [Troubleshooting → Which identity?](troubleshooting.md#1-which-identity-is-git-or-gh-using) |
| Respond to a leaked `ghp_` / `github_pat_` token | [Incident response → Identify and revoke](incident-response.md#1-a-token-leaked-identify-and-revoke) |
| See what a leaked token did | [Audit log → Find what a leaked token did](audit-logging.md#3-find-what-a-leaked-token-did) |
| Remove a secret from Git history | [Incident response → Purge](incident-response.md#3-purge-a-secret-from-git-history) |
| List owners, outside collaborators and members without 2FA | [Identity & access](identity-access.md#1-organization-review) |
| Let Actions deploy to Azure/AWS/GCP without stored keys | [Keys & secrets → OIDC](keys-secrets.md#3-oidc-from-actions-to-azure-aws-and-gcp) |
| Hunt for rogue deploy keys, webhooks, apps and runners | [Persistence & hunting](persistence-hunting.md) |
| Sync a fork or rebase a branch safely | [Git](repositories.md#2-fetch-pull-and-sync) |
| Get commits marked Verified | [Git → Signed commits](repositories.md#5-signed-commits) |

## Topics

The topic names match the cloud platforms ([Azure](../azure/index.md), [AWS](../aws/index.md), [Google Cloud](../gcp/index.md)) where GitHub has an equivalent.

| Topic | Covers | Page |
| --- | --- | --- |
| CLI & authentication | gh auth, token types and prefixes, scopes, SSH and signing keys | [CLI & Authentication](cli-authentication.md) |
| Identity & access | Org roles, base permission, teams, collaborators, PAT approval, apps | [Organizations & Access](identity-access.md) |
| Keys & secrets | Actions/environment secrets, `GITHUB_TOKEN`, OIDC, deploy keys | [Secrets, OIDC & Deploy Keys](keys-secrets.md) |
| Audit logging | Org audit log, key events, token hash search, security log | [Audit Log](audit-logging.md) |
| Security posture | Rulesets, CODEOWNERS, Actions policy, Dependabot, secret and code scanning | [Security Posture](security-posture.md) |
| Persistence & threat hunting | Deploy keys, webhooks, apps, runners, workflow backdoors | [Persistence & Hunting](persistence-hunting.md) |
| Incident response | Revoke tokens, contain accounts, purge history (filter-repo, BFG) | [Incident Response](incident-response.md) |
| Troubleshooting | Auth, push protection, rulesets, Actions and OIDC errors | [Troubleshooting](troubleshooting.md) |
| Local repository work | Clone, fetch/pull, fork sync, rebase, branches, signed commits | [Git](repositories.md) |

## All GitHub entries

<!-- cc:index platforms="GitHub" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Detection-as-Code Pipeline (Version Control, CI Validation & Staged Deploy)](../../tasks/detection-engineering/detection-as-code-pipeline.md) | Workflow | Microsoft Defender, Splunk, SentinelOne, GitHub, Linux | Sigma, KQL, SPL, S1QL, Python, Bash | Detection Engineering, Automation, Assurance |
| [Git: Clone, Sync a Fork, Branches, Rebase & Signed Commits](repositories.md) | Entry | GitHub | Bash | Administration, Automation, Troubleshooting |
| [GitHub Actions Secrets, Environments, OIDC & Deploy Keys](keys-secrets.md) | Entry | GitHub | Bash | Administration, Hardening, Investigation, Incident Response |
| [GitHub Audit Log & Security Log](audit-logging.md) | Entry | GitHub | Bash | Investigation, Incident Response, Forensics, Hardening |
| [GitHub CLI, Tokens & Authentication](cli-authentication.md) | Entry | GitHub | Bash | Administration, Automation, Incident Response |
| [GitHub Incident Response (Leaked Tokens, Compromised Accounts, Secret Purge)](incident-response.md) | Entry | GitHub | Bash, PowerShell | Incident Response, Forensics, Investigation |
| [GitHub Organizations, Teams & Repository Access](identity-access.md) | Entry | GitHub | Bash | Administration, Hardening, Investigation, Assurance |
| [GitHub Persistence & Threat Hunting](persistence-hunting.md) | Entry | GitHub | Bash | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [GitHub Security Posture (Rulesets, Actions Policy, Dependabot, Secret & Code Scanning)](security-posture.md) | Entry | GitHub | Bash | Assurance, Hardening, Investigation, Incident Response |
| [GitHub Troubleshooting (Auth, Push, Actions & OIDC Errors)](troubleshooting.md) | Entry | GitHub | Bash | Troubleshooting, Administration |

<!-- /cc:index -->
