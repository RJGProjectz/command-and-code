---
title: "Git: Clone, Sync a Fork, Branches, Rebase & Signed Commits"
platforms: [GitHub]
languages: [Bash]
tasks: [Administration, Automation, Troubleshooting]
category: Software
tags: [github, git, clone, fetch, pull, rebase, fork, upstream, gh repo sync, branches, force-with-lease, signed commits, ssh signing, gpg, allowed signers]
aliases: [git clone github repo, git fetch vs pull, git pull rebase, sync a fork with upstream, gh repo sync, git rebase onto main, git push force-with-lease, delete remote branch, git fetch prune, sign git commits with ssh key, git verify-commit, git allowed signers file]
difficulty: basic
verified: true
last_verified: 2026-10-18
---

# Git: Clone, Sync a Fork, Branches, Rebase & Signed Commits

Day-to-day repository work with `git` and `gh`, with the safe option first. Purging a secret from history is an incident step and lives in [Incident response](incident-response.md#3-purge-a-secret-from-git-history).

!!! warning "Before you run anything"
    Every command was checked against git-scm.com, docs.github.com and the GitHub CLI manual (2026-10-18); this guide does not run them against a live repository. Commands that rewrite or delete history or remote branches are marked **change**.

## 1. Clone

```bash
gh repo clone my-org/app                       # uses your gh protocol (https or ssh); a fork also gets an "upstream" remote
git clone git@github.com:my-org/app.git        # plain git over SSH
git clone --filter=blob:none https://github.com/my-org/app.git   # partial clone: history now, file contents on demand
git clone --depth 1 https://github.com/my-org/app.git            # shallow: latest commit only (CI, quick reads)
git remote -v
```

## 2. Fetch, pull and sync

`git fetch` downloads and changes nothing in your working tree; `git pull` is `fetch` + `merge` (or `rebase`). Fetching first lets you see what is coming.

```bash
git fetch --prune origin                       # also drop remote-tracking branches deleted on GitHub
git log --oneline HEAD..origin/main            # commits you are about to receive
git pull --rebase origin main                  # replay your local commits on top: no merge bubble
git config --global pull.ff only               # refuse surprise merges; choose rebase or merge yourself
git config --global fetch.prune true
```

**Sync a fork** with the repository it was forked from:

```bash
gh repo sync my-user/app-fork                  # update the fork on GitHub from its parent (fast-forward)
gh repo sync                                   # update the local clone's default branch from its remote
# Plain git
git remote add upstream https://github.com/my-org/app.git
git fetch upstream
git switch main && git merge --ff-only upstream/main && git push origin main
```

`gh repo sync --force` hard-resets the destination branch to the source and discards commits only the fork has (**change**).

## 3. Rebase and rewrite your own branch

```bash
git switch feature/login
git fetch origin
git rebase origin/main                         # replay the branch on the latest main; fix conflicts, then git rebase --continue
git rebase -i origin/main                      # squash/reword before review (interactive editor)
git push --force-with-lease                    # change: rewrites the remote branch only if nobody pushed since your last fetch
```

Rebase only branches **you** own. Never rewrite `main` or a branch others have built on; protect them with a [ruleset](security-posture.md#1-branch-protection-rulesets-and-codeowners) that blocks force pushes. `--force-with-lease` is the safe force: plain `--force` silently discards someone else's push.

Undo safely:

```bash
git reflog                                     # every position HEAD has been at: find the commit before the mistake
git reset --hard HEAD@{2}                      # change: local only; discards uncommitted work
git revert <commit>                            # public history: add a commit that undoes another
```

## 4. Branches

```bash
git switch -c feature/login                    # create and switch
git push -u origin feature/login               # publish and track (or: git config --global push.autoSetupRemote true)
git branch -vv                                 # local branches, upstream, ahead/behind
git branch --merged main                       # safe to delete
git branch -d feature/login                    # change: refuses if unmerged (-D forces)
git push origin --delete feature/login         # change: delete the remote branch
gh pr create --fill --base main
gh pr checkout 123                             # review someone's PR locally
```

## 5. Signed commits

GitHub marks a commit **Verified** when it is signed with a GPG, SSH or S/MIME key registered on the committer's account and the committer email is verified on that account.

```bash
# SSH signing (Git 2.34+): reuse or create an SSH key, then upload it as a signing key
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_github.pub
git config --global commit.gpgsign true
git config --global tag.gpgSign true
gh ssh-key add ~/.ssh/id_ed25519_github.pub --type signing --title "laptop signing"   # change

# GPG signing
git config --global --unset gpg.format
gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey 3AA5C34371567BD2
```

Verify locally. SSH signatures need an allowed-signers file mapping emails to keys:

```bash
printf '%s %s\n' "you@example.com" "$(cat ~/.ssh/id_ed25519_github.pub)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
git log --show-signature -3
git log --format='%h %G? %GS %s' -20           # G good, B bad, U good but untrusted, N none, E cannot check
git verify-commit HEAD && git verify-tag v1.2.0
```

Require signed commits on protected branches once every contributor and bot can sign (commits made in the GitHub web UI are signed by GitHub).

## Related

- [CLI & authentication](cli-authentication.md)
- [Security posture](security-posture.md)
- [Incident response: purge a secret](incident-response.md#3-purge-a-secret-from-git-history)
- [SSH key deployment](../../tasks/administration/ssh-key-deployment.md)

## Sources

- [git-fetch](https://git-scm.com/docs/git-fetch) · [git-pull](https://git-scm.com/docs/git-pull) · [git-rebase](https://git-scm.com/docs/git-rebase) · [git-push](https://git-scm.com/docs/git-push) · [git-config](https://git-scm.com/docs/git-config)
- [gh repo sync](https://cli.github.com/manual/gh_repo_sync) · [gh repo clone](https://cli.github.com/manual/gh_repo_clone)
- [Syncing a fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork)
- [Telling Git about your signing key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key)
- [About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
