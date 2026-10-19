---
title: GitHub CLI, Tokens & Authentication
platforms: [GitHub]
languages: [Bash]
tasks: [Administration, Automation, Incident Response]
category: Authentication
tags: [github, gh cli, gh auth, personal access token, fine-grained pat, ssh keys, signing keys, github app, github_token, token prefixes]
aliases: [gh auth login, gh auth status, gh auth refresh scopes, github fine-grained personal access token, github token prefix ghp github_pat, gh ssh-key add signing, github credential helper]
difficulty: basic
verified: true
last_verified: 2026-10-18
---

# GitHub CLI, Tokens & Authentication

`git` moves code; `gh` (GitHub CLI) talks to the GitHub API. Both need a credential, and the kind of credential decides what an attacker gets if it leaks.

| Credential | Prefix | Scoped to | Expires | Typical use |
| :--- | :--- | :--- | :--- | :--- |
| Personal access token (classic) | `ghp_` | Every repo and org the user can reach, limited by **scopes** | Optional (can be "no expiration") | Legacy scripts; avoid |
| Fine-grained personal access token | `github_pat_` | One owner (user or org), chosen repos, per-permission read/write | Required; org can cap lifetime | Scripts and local automation |
| OAuth app user token | `gho_` | Scopes the user granted to the app | Until revoked | `gh auth login --web`, third-party tools |
| GitHub App user-to-server / refresh | `ghu_` / `ghr_` | The app's permissions ∩ the user's access | 8 h (refresh token 6 months) | Apps acting as a user |
| GitHub App installation token | `ghs_` | The app's permissions on the installed repos | 1 hour | Bots, CI integrations |
| `GITHUB_TOKEN` (Actions) | `ghs_` | The running repo, permissions from the workflow | End of job (max 24 h) | Workflows |
| SSH key / deploy key | none (key pair) | User account / one repository | Never (until removed) | `git` over SSH |

The prefix tells you what you are dealing with when a token turns up in a log or a commit; see [Incident response](incident-response.md#1-a-token-leaked-identify-and-revoke).

!!! warning "Before you run anything"
    Every command was checked against the GitHub CLI manual, docs.github.com and git-scm.com (2026-10-18); this guide does not run them against a live account or organization. Commands that change state are marked **change**. Never paste a token on the command line: it lands in shell history.

## 1. Log in with gh

```bash
gh auth login --hostname github.com --git-protocol https --web   # browser device flow, token stored in the OS credential store
gh auth login --with-token < token.txt                           # non-interactive: read a PAT from stdin, never from argv
gh auth status                                                   # account, active host, token source, scopes, storage location
gh auth refresh --scopes read:audit_log,admin:org                # change: add scopes to the gh OAuth token
gh auth refresh --remove-scopes delete_repo                      # change: drop a scope you no longer need
gh auth switch                                                   # change active account when several are logged in
gh auth setup-git                                                # use gh as the git credential helper for HTTPS
gh auth logout --hostname github.com                             # change: remove the stored token from this machine
```

- `gh` stores the token in the system credential store (Windows Credential Manager, macOS Keychain, libsecret). Only `--insecure-storage`, or a missing credential store, puts it in a plain-text `hosts.yml`; `gh auth status` shows which.
- A classic PAT passed with `--with-token` needs at least `repo`, `read:org` and `gist`.
- `GH_TOKEN` / `GITHUB_TOKEN` in the environment take over from the stored login. In Actions, set `GH_TOKEN: ${{ github.token }}` so `gh` uses the job token.
- `gh auth logout` removes the local copy; it does **not** revoke the token on GitHub.

## 2. Pick the right token

1. **Interactive work:** `gh auth login --web` (OAuth, scoped, revocable under *Settings → Applications*).
2. **Scripts:** a **fine-grained PAT** with only the repositories and permissions the script needs, and an expiry. Orgs can require approval for fine-grained PATs and block classic PATs (*Org settings → Personal access tokens*).
3. **Services and bots:** a **GitHub App** (short-lived `ghs_` tokens, no seat, auditable as the app).
4. **CI:** `GITHUB_TOKEN` with an explicit `permissions:` block, plus **OIDC** for cloud access instead of stored cloud keys ([Keys & secrets](keys-secrets.md#3-oidc-from-actions-to-azure-aws-and-gcp)).

Classic scopes worth knowing: `repo` (full private repo access), `admin:org`, `admin:repo_hook`, `admin:public_key`, `workflow` (edit `.github/workflows`), `delete_repo`, `read:audit_log`. A classic token with `repo` + `workflow` can rewrite CI; treat it like a deploy credential.

## 3. Who am I and what can this token do?

```bash
gh api user --jq '{login, id, type, two_factor_authentication}'
gh api -i user 2>/dev/null | grep -i '^x-oauth-scopes:'           # classic/OAuth scopes (fine-grained tokens show none)
gh api -i user 2>/dev/null | grep -i '^github-authentication-token-expiration:'
gh api rate_limit --jq '.resources.core'                         # remaining calls; 60/h means you are anonymous
gh api user/orgs --jq '.[].login'
```

## 4. SSH, GPG and SSH signing keys

```bash
ssh-keygen -t ed25519 -C "you@example.com" -f ~/.ssh/id_ed25519_github
gh ssh-key add ~/.ssh/id_ed25519_github.pub --title "laptop-2026" --type authentication   # change
gh ssh-key add ~/.ssh/id_ed25519_github.pub --title "laptop-2026 signing" --type signing  # change: same key may also sign commits
gh ssh-key list
gh gpg-key list
ssh -T git@github.com                                             # expect "Hi <user>! You've successfully authenticated"
```

One key per device makes revocation surgical. Use a passphrase or a hardware-backed key (`-t ed25519-sk`). Signed commits are set up in [Git: clone, sync, branches & signing](repositories.md#5-signed-commits).

## 5. Git over HTTPS

`git` does not read `GH_TOKEN`. It asks a credential helper: Git Credential Manager (Git for Windows default), the macOS keychain helper, or `gh auth setup-git`. List what git stored with:

```bash
git config --show-origin --get-all credential.helper
printf 'protocol=https\nhost=github.com\n\n' | git credential fill   # prints the stored username/password: run only on your own machine
```

Never embed a token in a remote URL (`https://TOKEN@github.com/...`): it is written in plain text to `.git/config`.

## Related

- [Identity & access](identity-access.md)
- [Keys & secrets](keys-secrets.md)
- [Azure CLI & authentication](../azure/cli-authentication.md)
- [Credential rotation after compromise](../../tasks/incident-response/credential-rotation-after-compromise.md)

## Sources

- [gh auth login](https://cli.github.com/manual/gh_auth_login) · [gh ssh-key add](https://cli.github.com/manual/gh_ssh-key_add)
- [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [About authentication to GitHub (token prefixes)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github)
- [Scopes for OAuth apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
