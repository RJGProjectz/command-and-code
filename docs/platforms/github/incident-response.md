---
title: GitHub Incident Response (Leaked Tokens, Compromised Accounts, Secret Purge)
platforms: [GitHub]
languages: [Bash, PowerShell]
tasks: [Incident Response, Forensics, Investigation]
category: Incident Response
tags: [github, incident response, leaked token, revoke token, credentials revoke api, compromised account, git filter-repo, bfg repo-cleaner, sensitive data removal, force push, github support]
aliases: [github token leaked what to do, revoke github personal access token, github credentials revoke api, remove secret from git history, git filter-repo sensitive-data-removal, bfg replace-text passwords, github remove sensitive data, github compromised account response, revoke deploy key, github pull request refs cached views]
difficulty: advanced
verified: true
last_verified: 2026-10-18
---

# GitHub Incident Response

Order matters: **revoke the credential first, investigate second, rewrite history last**. A rewritten history does not un-leak a secret that was cloned, forked, cached or scraped within minutes of the push.

!!! warning "Before you run anything"
    Every command was checked against docs.github.com, git-scm.com, the git-filter-repo manual and the BFG documentation (2026-10-18); this guide does not run them against a live repository. Steps marked **change** alter accounts or rewrite history. History rewrites are destructive: work in a fresh clone, keep a mirror backup, and agree a freeze with everyone who pushes to the repo.

## 1. A token leaked: identify and revoke

| Prefix | What it is | Revoke |
| :--- | :--- | :--- |
| `ghp_` | Classic PAT | Owner: *Settings → Developer settings → Personal access tokens* |
| `github_pat_` | Fine-grained PAT | Owner, or org owner: *Org settings → Personal access tokens → Active tokens* |
| `gho_` | OAuth app token | Owner: *Settings → Applications → Authorized OAuth Apps → Revoke* |
| `ghu_` / `ghr_` | GitHub App user token / refresh token | Owner: *Settings → Applications → Authorized GitHub Apps* |
| `ghs_` | App installation token or `GITHUB_TOKEN` | Expires within 1 h / at job end; for an app, rotate its private key and suspend the installation |
| SSH / deploy key | Key pair | `gh ssh-key delete <id>` / `gh repo deploy-key delete <id>` |

If the token is not yours (found in a public repo, paste site or log), revoke it with the **credentials revoke API**. It takes no authentication (an authenticated call returns 403), up to 1000 tokens per call, and notifies the owner. Keep the token out of shell history and argv:

```bash
read -rs TOKEN
jq -n --arg t "$TOKEN" '{credentials: [$t]}' | curl -sS -X POST https://api.github.com/credentials/revoke \
  -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' --data-binary @-
unset TOKEN
```

The PowerShell equivalent of the audit log token hash (see [Audit log → find what a leaked token did](audit-logging.md#3-find-what-a-leaked-token-did)):

```powershell
$secureToken = Read-Host -AsSecureString -Prompt 'Token'
$plainToken = [System.Net.NetworkCredential]::new('', $secureToken).Password
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashedToken = [Convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainToken)))
Remove-Variable -Name plainToken
"hashed_token:`"$hashedToken`""
```

Then: search the audit log by that hash, list every repo the token could reach, and rotate any secret those repos' workflows held (assume a token with `repo` + `workflow` could read them).

## 2. Contain a compromised account or org

1. **User account:** reset password, sign out all sessions (*Settings → Sessions*), review and regenerate 2FA recovery codes, delete unknown SSH/GPG/signing keys, PATs, OAuth and GitHub App authorizations, and check emails on the account.
2. **Org (owner):** remove the user from the org or block them, revoke their fine-grained PATs and SAML credential authorizations ([Identity & access](identity-access.md#3-personal-access-tokens-against-the-org)).
3. **Persistence:** remove keys, webhooks, apps and runners found with [Persistence & hunting](persistence-hunting.md#2-keys-hooks-apps-and-runners-across-the-org).
4. **Secrets:** rotate every Actions, environment and Dependabot secret in repos the identity could write to, and the cloud credentials behind OIDC trusts it could trigger.
5. **Code:** diff `main` and release tags against the last known-good commit, starting with `.github/workflows`; check releases and packages published in the window.

```bash
gh ssh-key list && gh gpg-key list
gh ssh-key delete <key-id> --yes                     # change
gh api -X DELETE "orgs/my-org/hooks/<hook-id>"       # change
gh api -X DELETE "repos/my-org/app/actions/runners/<runner-id>"   # change
```

## 3. Purge a secret from Git history

Do this **after** revocation, and only when the content itself must go (a key that cannot be rotated, personal data, or a policy requirement).

**git filter-repo** (2.47 or later for `--sensitive-data-removal`), in a fresh clone:

```bash
git clone --mirror https://github.com/my-org/app.git app-backup.git      # keep an untouched backup
git clone https://github.com/my-org/app.git app && cd app
git filter-repo --sensitive-data-removal --invert-paths --path config/prod.env        # remove a file everywhere (add --path for old names)
git filter-repo --sensitive-data-removal --replace-text ../expressions.txt           # or replace strings in every blob
grep -c '^refs/pull/.*/head$' .git/filter-repo/changed-refs                          # how many PRs still hold the old commits
git push --force --mirror origin                                                     # change: --mirror implies --force; refs/pull/* pushes fail by design
```

`expressions.txt` takes one entry per line: a literal (`AKIAEXAMPLE`, replaced with `***REMOVED***`), `literal==>REPLACEMENT`, or `regex:pattern==>REPLACEMENT`. Branch protection may reject the forced push: lift it for the window and restore it straight after.

**BFG Repo-Cleaner** (Java, faster on huge repos, but it leaves the current `HEAD` commit untouched, so remove the secret in a normal commit first):

```bash
git clone --mirror https://github.com/my-org/app.git
java -jar bfg.jar --delete-files prod.env app.git
java -jar bfg.jar --replace-text passwords.txt app.git
cd app.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push                                                                             # change: a mirror clone pushes all refs
```

**After the push:**

- Open a GitHub Support ticket with the repo, the number of affected PRs, the **first changed commits** from filter-repo output and any orphaned LFS objects. Support dereferences PR refs, removes cached views and runs garbage collection.
- GitHub cannot clean **forks**: ask fork owners to delete or re-clone.
- Every collaborator must **re-clone** (or rebase, never merge, old branches). A single merge of an old branch brings the secret back.
- Add the file to `.gitignore`, turn on push protection, and close the secret scanning alert as *revoked*.

## Related

- [Credential rotation after compromise](../../tasks/incident-response/credential-rotation-after-compromise.md)
- [Audit log](audit-logging.md) · [Persistence & hunting](persistence-hunting.md)
- [Git: rebase and force-with-lease](repositories.md#3-rebase-and-rewrite-your-own-branch)
- [Cloud IR cheat sheet](../../references/cloud-ir-cheat-sheet.md)

## Sources

- [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [REST: revoke a list of credentials](https://docs.github.com/en/rest/credentials/revoke)
- [git-filter-repo manual](https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [Recovering an account with 2FA / securing your account](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/preventing-unauthorized-access)
