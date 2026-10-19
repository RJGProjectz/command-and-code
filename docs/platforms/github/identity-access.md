---
title: GitHub Organizations, Teams & Repository Access
platforms: [GitHub]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Assurance]
category: Identity
tags: [github, organization, owners, teams, outside collaborators, repository roles, base permissions, two-factor, fine-grained pat approval, github apps, oauth apps, saml sso]
aliases: [github org owners list, github outside collaborators, github members without 2fa, github team repository permissions, github base permission, review github apps installed, review oauth app access, github pat approval requests, github saml credential authorizations]
difficulty: intermediate
verified: true
last_verified: 2026-10-18
---

# GitHub Organizations, Teams & Repository Access

Access to a repository in an organization is the **highest** of: the org **base permission**, every **team** the user is in, a **direct collaborator** grant, and **owner** status (owners can do everything). Apps and tokens then act within what their owner can reach.

| Layer | Roles | Where it is set |
| :--- | :--- | :--- |
| Organization | Owner, Member, Billing manager, Security manager, custom org roles | *Org settings → People / Org roles* |
| Base permission | No permission, Read, Write, Admin (applies to **every** member on every repo) | *Org settings → Member privileges* |
| Team | Team grants a repo role; nested teams inherit parent grants | *Org → Teams* |
| Repository | Read, Triage, Write, Maintain, Admin, custom repo roles | *Repo settings → Collaborators and teams* |
| Outside collaborator | Any repo role on named repos, not an org member | *Repo settings* |

!!! warning "Before you run anything"
    Every command was checked against docs.github.com REST reference and the GitHub CLI manual (2026-10-18); this guide does not run them against a live organization. Commands that change state are marked **change**. Most org reads need an org owner and the `read:org` scope (`admin:org` for settings).

## 1. Organization review

```bash
ORG=my-org
gh api "orgs/$ORG" --jq '{default_repository_permission, two_factor_requirement_enabled, members_can_create_public_repositories, members_can_create_repositories, web_commit_signoff_required}'
gh api "orgs/$ORG/members?role=admin" --paginate --jq '.[].login'          # owners: keep this list short
gh api "orgs/$ORG/members?filter=2fa_disabled" --paginate --jq '.[].login'  # should be empty
gh api "orgs/$ORG/outside_collaborators" --paginate --jq '.[].login'
gh api "orgs/$ORG/invitations" --paginate --jq '.[] | {login, email, role, inviter: .inviter.login, created_at}'
```

Hardening defaults: base permission **Read** or **No permission**; require 2FA; restrict who can create public repos, invite outside collaborators, change repo visibility and delete or transfer repos.

## 2. Teams and who can reach a repository

```bash
gh api "orgs/$ORG/teams" --paginate --jq '.[] | {slug, privacy, parent: .parent.slug}'
gh api "orgs/$ORG/teams/platform-admins/members" --paginate --jq '.[].login'
gh api "orgs/$ORG/teams/platform-admins/repos" --paginate --jq '.[] | {name: .full_name, role: .role_name}'

# Everyone with access to one repo, and how they got it
gh api "repos/$ORG/app/collaborators?affiliation=all" --paginate --jq '.[] | {login, role: .role_name}'
gh api "repos/$ORG/app/collaborators?affiliation=outside" --paginate --jq '.[].login'
gh api "repos/$ORG/app/teams" --jq '.[] | {slug, permission}'
```

`Maintain` can manage settings except destructive ones; `Admin` can disable branch protection, add deploy keys and webhooks, and change secrets. Keep repo `Admin` to a team, not individuals.

Remove access (**change**):

```bash
gh api -X DELETE "repos/$ORG/app/collaborators/old-contractor"
gh api -X DELETE "orgs/$ORG/outside_collaborators/old-contractor"   # from every repo in the org
gh api -X DELETE "orgs/$ORG/memberships/departed-user"              # removes org membership and team seats
```

## 3. Personal access tokens against the org

Owners decide whether fine-grained PATs need approval and whether classic PATs may access the org (*Org settings → Personal access tokens*). Review pending requests and approved tokens in that page. The REST endpoints (`GET /orgs/{org}/personal-access-tokens`, `GET /orgs/{org}/personal-access-token-requests`, `POST ... {"action":"revoke","pat_ids":[...]}`) can be called only by a **GitHub App**, so script them from an app, not with `gh` under a user token.

Orgs on Enterprise Cloud with **SAML SSO** list every PAT and SSH key a member has authorized for the org:

```bash
gh api "orgs/$ORG/credential-authorizations" --paginate --jq '.[] | {login, credential_type, credential_id, scopes, credential_accessed_at, authorized_credential_expires_at}'
gh api -X DELETE "orgs/$ORG/credential-authorizations/<credential-id>"     # change: de-authorize one credential for this org
```

## 4. GitHub Apps and OAuth apps

| | GitHub App | OAuth app |
| :--- | :--- | :--- |
| Installed / approved by | Owner installs on chosen repos | Each user authorizes; org owners approve under **OAuth app access restrictions** |
| Acts as | Itself (`ghs_`) or the user (`ghu_`) | Always the user (`gho_`) |
| Permissions | Fine-grained, listed per install | Classic scopes (often `repo`) |

```bash
gh api "orgs/$ORG/installations" --paginate --jq '.installations[] | {app_slug, id, repository_selection, permissions, events, created_at, updated_at}'
```

Questions for every installation: who requested it, does it need `contents: write` / `administration` / `workflows`, is `repository_selection` **all** when **selected** would do, when was it last used. OAuth apps have no org listing API: review *Org settings → Third-party access → OAuth application policy* (keep restrictions **on**) and each user's *Settings → Applications*.

## Related

- [CLI & authentication](cli-authentication.md)
- [Security posture: branch protection and rulesets](security-posture.md#1-branch-protection-rulesets-and-codeowners)
- [Persistence & hunting](persistence-hunting.md)
- [Azure identity & access](../azure/identity-access.md)

## Sources

- [Repository roles for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization)
- [REST: organization members](https://docs.github.com/en/rest/orgs/members) · [outside collaborators](https://docs.github.com/en/rest/orgs/outside-collaborators) · [teams](https://docs.github.com/en/rest/teams/teams)
- [REST: personal access tokens (org)](https://docs.github.com/en/rest/orgs/personal-access-tokens)
- [REST: SAML credential authorizations](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#list-saml-sso-authorizations-for-an-organization)
- [REST: list app installations for an organization](https://docs.github.com/en/rest/orgs/orgs#list-app-installations-for-an-organization)
