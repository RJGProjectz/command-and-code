---
title: Azure CLI, Az PowerShell & Authentication
platforms: [Azure]
languages: [Bash, PowerShell]
tasks: [Administration, Automation, Incident Response]
category: Authentication
tags: [azure, az cli, az powershell, service principal, managed identity, authentication, tokens]
aliases: [az login, connect-azaccount, azure service principal login, azure managed identity token, switch azure subscription]
difficulty: basic
verified: true
last_verified: 2026-10-12
---

# Azure CLI, Az PowerShell & Authentication

Every Azure task starts with an authenticated session in the right tenant and subscription. Use the **Azure CLI** (`az`) in Bash or PowerShell, or the **Az PowerShell** module. Both read the same Azure Resource Manager (ARM) API, so a command in one has an equivalent in the other.

!!! warning "Before you run anything"
    Every command was checked against the Azure CLI reference and Microsoft Learn (2026-10-12); this guide does not run them against a live tenant. Run read-only commands first. Commands that change state are marked **change**.

## 1. Install and check the tools

```bash
az version                       # CLI and extension versions
az upgrade                       # update the CLI (Windows MSI / Homebrew / apt)
```

```powershell
Install-Module Az -Scope CurrentUser -Repository PSGallery
Get-InstalledModule Az | Select-Object Name, Version
```

## 2. Sign in

| Identity | Azure CLI | Az PowerShell |
| :--- | :--- | :--- |
| Interactive user | `az login` | `Connect-AzAccount` |
| Device code (no browser on the host) | `az login --use-device-code` | `Connect-AzAccount -UseDeviceAuthentication` |
| Specific tenant | `az login --tenant <tenant-id>` | `Connect-AzAccount -Tenant <tenant-id>` |
| Service principal + certificate | `az login --service-principal -u <app-id> --certificate <cert.pem> --tenant <tenant-id>` | `Connect-AzAccount -ServicePrincipal -ApplicationId <app-id> -CertificateThumbprint <thumb> -Tenant <tenant-id>` |
| Managed identity (on an Azure VM, Function, Automation) | `az login --identity` | `Connect-AzAccount -Identity` |
| User-assigned managed identity | `az login --identity --client-id <client-id>` | `Connect-AzAccount -Identity -AccountId <client-id>` |

Prefer certificates or managed identities over client secrets. Never put a secret on the command line in a shared shell; history files keep it.

## 3. Pick the subscription

```bash
az account list --output table                 # every subscription you can see
az account show --output table                 # the current context
az account set --subscription "<name-or-id>"   # switch
```

```powershell
Get-AzSubscription | Select-Object Name, Id, TenantId, State
Get-AzContext
Set-AzContext -Subscription "<name-or-id>"
```

!!! tip "One context per script"
    Scripts should call `az account set` / `Set-AzContext` explicitly. A script that inherits whatever subscription the last person used is the classic way to change the wrong environment.

## 4. Who am I and what can I do?

```bash
az ad signed-in-user show --query "{upn:userPrincipalName, id:id}"   # user sessions only
az account show --query "{tenant:tenantId, sub:id, user:user.name, type:user.type}"
az role assignment list --assignee "<object-id-or-upn>" --all --output table
```

```powershell
(Get-AzContext).Account
Get-AzRoleAssignment -SignInName user@contoso.com | Select-Object RoleDefinitionName, Scope
```

## 5. Tokens

Get a raw access token to call ARM or Microsoft Graph with `curl` or `Invoke-RestMethod`:

```bash
az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
az account get-access-token --resource-type ms-graph --query expiresOn -o tsv
```

```powershell
$token = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/'
# Az 12+ returns Token as a SecureString; convert only in memory, never log it
```

On a VM, the managed-identity token comes from the Instance Metadata Service (IMDS). Attackers who land on a VM query the same endpoint, so it is also an investigation lead:

```bash
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## 6. Known locations

| Path | Contents |
| :--- | :--- |
| `~/.azure/` (`%USERPROFILE%\.azure\`) | Azure CLI profile, config and token cache (`msal_token_cache.*`, `azureProfile.json`) |
| `~/.Azure/` (`%USERPROFILE%\.Azure\`) | Az PowerShell context (`AzureRmContext.json`) and token cache |
| `AZURE_CONFIG_DIR` | Overrides the CLI folder; useful for isolated sessions per tenant |

Treat these folders as credentials. On a compromised admin workstation, collect them as evidence and then [revoke the sessions](incident-response.md#1-contain-the-identity).

## 7. Sign out and clean up

```bash
az logout
az account clear          # remove all cached accounts
```

```powershell
Disconnect-AzAccount
Clear-AzContext -Force
```

## Related

- [Identity & access (RBAC)](identity-access.md)
- [Microsoft 365 → Entra ID](../microsoft-365/entra.md) for users, sign-ins and app registrations
- [Azure troubleshooting → authentication errors](troubleshooting.md#1-authentication-and-authorization-errors)

## Sources

- [Sign in with Azure CLI](https://learn.microsoft.com/cli/azure/authenticate-azure-cli)
- [Sign in with Azure PowerShell](https://learn.microsoft.com/powershell/azure/authenticate-azureps)
- [Managed identities: acquire a token on a VM](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
