---
title: GitHub Actions Secrets, Environments, OIDC & Deploy Keys
platforms: [GitHub]
languages: [Bash]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Secrets
tags: [github, actions secrets, environments, required reviewers, oidc, workload identity federation, github_token permissions, deploy keys, dependabot secrets, azure login, aws configure credentials, google github actions auth]
aliases: [gh secret list org, github environment secrets, github actions oidc azure, github actions oidc aws, github actions oidc gcp, github_token permissions block, id-token write, github deploy key read only, gh repo deploy-key list]
difficulty: intermediate
verified: true
last_verified: 2026-10-18
---

# GitHub Actions Secrets, Environments, OIDC & Deploy Keys

| Store | Visible to | Use it for |
| :--- | :--- | :--- |
| **Organization secret** | Repos you select (or all private/all repos) | Shared, low-value values only |
| **Repository secret** | Every workflow in the repo, on any branch that can run a workflow | Values not tied to a deployment |
| **Environment secret** | Only jobs that name the environment, after its protection rules pass | Deployment credentials |
| **Dependabot secret** | Only Dependabot runs (private registries) | Registry tokens |
| **Variable** | Same scopes, not masked | Non-secret configuration |

Secrets are encrypted at rest and masked in logs, but **any workflow code that can read a secret can exfiltrate it**. The real controls are who can change workflow files and which branches can reach an environment.

!!! warning "Before you run anything"
    Every command and workflow snippet was checked against docs.github.com and the GitHub CLI manual (2026-10-18); this guide does not run them against a live repository or cloud tenant. Commands that change state are marked **change**. Pass secret values on stdin or from a file, never as an argument.

## 1. Inventory secrets and environments

```bash
ORG=my-org; REPO=my-org/app
gh secret list --org "$ORG"                       # names, updated date, visibility
gh secret list --repo "$REPO"
gh secret list --repo "$REPO" --env production
gh secret list --repo "$REPO" --app dependabot
gh variable list --repo "$REPO"
gh api "repos/$REPO/environments" --jq '.environments[] | {name, protection_rules: [.protection_rules[].type], branch_policy: .deployment_branch_policy}'
```

Set or rotate (**change**):

```bash
gh secret set DEPLOY_TOKEN --repo "$REPO" --env production < ./new-token.txt
gh secret delete OLD_KEY --repo "$REPO"
```

Protect production environments with **required reviewers**, **prevent self-review**, and **deployment branches** limited to `main` or protected tags.

## 2. Least-privilege `GITHUB_TOKEN`

Set the org and repo default to **read** (*Settings → Actions → General → Workflow permissions*) and turn off "Allow GitHub Actions to create and approve pull requests". Then grant per job:

```yaml
permissions: {}            # workflow level: nothing by default
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<full-40-character-commit-sha>  # vX.Y.Z: pin to the SHA of the release you reviewed
```

```bash
gh api "orgs/$ORG/actions/permissions/workflow" --jq '{default_workflow_permissions, can_approve_pull_request_reviews}'
gh api "repos/$REPO/actions/permissions/workflow"
```

## 3. OIDC from Actions to Azure, AWS and GCP

OIDC replaces stored cloud keys with a short-lived token the job exchanges for cloud credentials. The job needs `id-token: write`; the cloud side trusts a **subject** (`sub`) claim:

| Workflow context | `sub` claim |
| :--- | :--- |
| Environment | `repo:my-org/app:environment:production` |
| Branch | `repo:my-org/app:ref:refs/heads/main` |
| Tag | `repo:my-org/app:ref:refs/tags/v1.2.0` |
| Pull request | `repo:my-org/app:pull_request` |

Trust **environment** or **exact branch** subjects, never `repo:my-org/*`. Wildcards let any branch, or a fork PR in some setups, take the role.

```yaml
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      # Azure: federated credential on an app registration or user-assigned managed identity
      # (issuer https://token.actions.githubusercontent.com, audience api://AzureADTokenExchange)
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      # AWS: IAM OIDC provider token.actions.githubusercontent.com, audience sts.amazonaws.com,
      # role trust condition on token.actions.githubusercontent.com:sub
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gha-deploy
          aws-region: us-east-1
      # GCP: Workload Identity Federation pool + provider with an attribute condition on the repository
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123456789/locations/global/workloadIdentityPools/github/providers/github
          service_account: deploy@my-project.iam.gserviceaccount.com
```

Tags such as `@v2` are shown for readability; pin them to a commit SHA in real workflows. The IDs are placeholders. Cloud-side checks: Azure federated credentials are on the app or managed identity ([Azure identity](../azure/identity-access.md)); AWS role trust policies ([AWS IAM](../aws/identity-access.md)); GCP provider `attribute.repository` conditions ([GCP IAM](../gcp/identity-access.md)).

## 4. Deploy keys

A deploy key is an SSH key bound to **one** repository, read-only unless "Allow write access" is ticked. It belongs to no user, so it survives staff changes. Inventory it like a service account.

```bash
gh repo deploy-key list --repo "$REPO"
gh api "repos/$REPO/keys" --jq '.[] | {id, title, read_only, created_at, added_by, last_used}'
gh repo deploy-key add ./ci_ed25519.pub --repo "$REPO" --title "ci-readonly-2026"     # change: read-only by default
gh repo deploy-key delete <key-id> --repo "$REPO"                                     # change
```

Prefer a GitHub App over a write deploy key for automation that pushes.

## 5. Where secrets leak

- `run: echo ${{ secrets.X }} | base64` defeats masking. Review workflow diffs for secret use outside the step that needs it.
- `pull_request_target` and `workflow_run` run with the base repo's secrets; checking out the PR head there runs untrusted code with them ([Security posture](security-posture.md#3-actions-policy)).
- Self-hosted runners keep files between jobs unless they are ephemeral.
- Secrets committed to code: [secret scanning](security-posture.md#5-secret-scanning-and-push-protection) and the [leaked-secret purge](incident-response.md#3-purge-a-secret-from-git-history).

## Related

- [Azure Key Vault](../azure/keys-secrets.md) · [AWS KMS & Secrets Manager](../aws/keys-secrets.md) · [GCP Secret Manager](../gcp/keys-secrets.md)
- [Linux service secrets storage](../../tasks/administration/linux-service-secrets-storage.md)
- [Credential rotation after compromise](../../tasks/incident-response/credential-rotation-after-compromise.md)

## Sources

- [Using secrets in GitHub Actions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)
- [Managing environments for deployment](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [Controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token)
- [gh secret](https://cli.github.com/manual/gh_secret) · [gh repo deploy-key](https://cli.github.com/manual/gh_repo_deploy-key)
- [Managing deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys)
