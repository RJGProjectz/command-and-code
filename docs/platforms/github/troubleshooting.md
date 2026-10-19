---
title: GitHub Troubleshooting (Auth, Push, Actions & OIDC Errors)
platforms: [GitHub]
languages: [Bash]
tasks: [Troubleshooting, Administration]
category: Troubleshooting
tags: [github, troubleshooting, permission denied publickey, 403, resource not accessible by integration, saml sso authorization, push protection gh013, non-fast-forward, unverified commit, rate limit, oidc errors]
aliases: [git permission denied publickey github, github 403 resource not accessible by integration, github saml enforcement token authorize, gh013 repository rule violations, push cannot contain secrets, rejected non-fast-forward, github commit unverified, github api rate limit exceeded, not authorized to perform sts assumerolewithwebidentity, aadsts70021 no matching federated identity]
difficulty: intermediate
verified: true
last_verified: 2026-10-18
---

# GitHub Troubleshooting

Most GitHub failures are one of: the wrong credential is used, the credential lacks a permission, an org policy blocks it, or a rule on the branch rejects the push. Start by finding out **which identity** the tool is using.

!!! warning "Before you run anything"
    Every command was checked against docs.github.com, the GitHub CLI manual and git-scm.com (2026-10-18); this guide does not run them against a live account. The diagnostics here are read-only.

## 1. Which identity is git or gh using?

```bash
gh auth status                                           # account, token source (keyring / GH_TOKEN), scopes
env | grep -E '^(GH|GITHUB)_TOKEN=' | cut -d= -f1         # an env token overrides the stored login
git remote -v                                            # https:// uses the credential helper, git@ uses SSH
git config --show-origin --get-all credential.helper
ssh -T git@github.com                                    # SSH: which account this key maps to
ssh -vT git@github.com 2>&1 | grep -E 'Offering|Authenticated|identity file'
GIT_TRACE=1 GIT_CURL_VERBOSE=1 git ls-remote origin 2>&1 | grep -iE '^< HTTP|www-authenticate' | head
```

## 2. Error lookup

| Error | Cause | Fix |
| :--- | :--- | :--- |
| `Permission denied (publickey)` | No key offered, or the key is not on any account | `ssh-add -l`; add the key with `gh ssh-key add`; set `IdentityFile` for `Host github.com` in `~/.ssh/config` |
| `ERROR: Repository not found` / HTTP 404 on a repo that exists | Your identity cannot see it (private repos answer 404, not 403) | Check the account in step 1; request access; for a fine-grained PAT, add the repo to the token |
| `Resource not accessible by integration` (403) | `GITHUB_TOKEN` or app token lacks the permission | Add it to the job's `permissions:` block, or check the org's read-only default |
| `Resource not accessible by personal access token` | Fine-grained PAT missing a permission or the repo | Edit the token; the org may also need to approve it |
| `Resource protected by organization SAML enforcement` | Token or SSH key not authorized for the SAML org | *Settings → Developer settings → token → Configure SSO → Authorize*; re-run `gh auth login` |
| `GH013: Repository rule violations found` … `Push cannot contain secrets` | Push protection found a secret | Remove it from **every** commit in the push (`git reset` / `git rebase -i`), rotate it; bypass only for false positives |
| `GH013` … `Changes must be made through a pull request` / signed commits required | Ruleset on the branch | `gh ruleset check <branch>`; push to a branch and open a PR; sign commits |
| `! [rejected] main -> main (non-fast-forward)` | The remote has commits you do not | `git pull --rebase` then push ([Git](repositories.md#2-fetch-pull-and-sync)) |
| `protected branch hook declined` / force push rejected | Branch protection blocks force pushes | Never force-push `main`; use a PR |
| `API rate limit exceeded` | 60 req/h unauthenticated, 5000 req/h for a user token | Authenticate; check `gh api rate_limit` |
| Commit shows **Unverified** | Signing key not on the account, email mismatch, or key expired | [Signed commits](repositories.md#5-signed-commits) |
| `refusing to allow an OAuth App to create or update workflow` | Token lacks the `workflow` scope | `gh auth refresh -s workflow` (only if you must edit workflows) |

## 3. Actions OIDC to the cloud

```yaml
# Temporary debug step: print the non-secret claims of the job's OIDC token
- name: Show OIDC claims
  run: |
    TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)
    printf '%s' "$TOKEN" | jq -R 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | {sub, aud, repository, ref, environment, job_workflow_ref}'
```

| Symptom | Usual cause |
| :--- | :--- |
| `Unable to get ACTIONS_ID_TOKEN_REQUEST_URL` | Job lacks `permissions: id-token: write` |
| AWS `Not authorized to perform sts:AssumeRoleWithWebIdentity` | Trust policy `sub` / `aud` does not match the claims above |
| Azure `AADSTS70021: No matching federated identity record found` | Federated credential subject differs (environment vs branch) or wrong issuer/audience |
| GCP `The given credential is rejected by the attribute condition` | Provider `attribute_condition` does not match the repository or ref |

Compare the printed `sub` character for character with the cloud trust. Jobs that use an `environment:` get the environment subject, not the branch one. Remove the debug step afterwards.

## Related

- [CLI & authentication](cli-authentication.md)
- [Keys & secrets: OIDC](keys-secrets.md#3-oidc-from-actions-to-azure-aws-and-gcp)
- [AWS troubleshooting](../aws/troubleshooting.md) · [Azure troubleshooting](../azure/troubleshooting.md)

## Sources

- [Troubleshooting SSH](https://docs.github.com/en/authentication/troubleshooting-ssh/error-permission-denied-publickey)
- [Working with push protection from the command line](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line)
- [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [git environment variables (GIT_TRACE)](https://git-scm.com/book/en/v2/Git-Internals-Environment-Variables)
