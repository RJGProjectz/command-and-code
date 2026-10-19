---
title: Store Service Secrets & Keys on Windows
type: workflow
platforms:
  - Windows
  - Windows Server
  - Active Directory
languages:
  - PowerShell
  - CMD
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-18
difficulty: intermediate
category: Identity
tags:
  - secrets
  - credentials
  - dpapi
  - secretmanagement
  - secretstore
  - credential manager
  - gmsa
  - rotation
aliases: [where to store service password windows, windows service secrets, dpapi machine scope, dpapi localmachine, ProtectedData Protect LocalMachine, Export-Clixml credential service, ConvertFrom-SecureString dpapi, SecretManagement SecretStore service, Get-Secret service account, Unlock-SecretStore automation, credential manager service account, cmdkey generic credential, service logon password lsa secret, Set-Service -Credential rotate password, rotate service account password, gmsa no password, who can read service secret windows, azure key vault managed identity powershell]
---

# Store Service Secrets & Keys on Windows

*"Where do I keep the API key so only the service can read it?"* *"The `Export-Clixml` file works for me but not for
the service."* *"How do I rotate the service password everywhere?"* This workflow picks a store for each secret a
Windows service needs, shows who can read it, and gives the rotation steps for each store, from PowerShell and `cmd`.
It builds on [Windows service accounts with least privilege](windows-service-accounts-least-privilege.md), which creates
the service identity (`NT SERVICE\AppSvc` or a gMSA) and the locked-down `C:\ProgramData\AppSvc\secrets` folder used
here.

!!! warning "Before you run anything"
    These commands create and replace secrets. Keep the old value until the service has restarted and works with the
    new one, and never type a secret as a command argument (it lands in PSReadLine history and process command
    lines): every example reads it with `Read-Host -AsSecureString`. Commands are checked against the Microsoft Learn
    pages listed under Sources; they were not run on a live host for this page.

## Pick a store

| Store | Who can decrypt or read it | Good for |
| :--- | :--- | :--- |
| **No secret**: virtual account or gMSA | Nobody: Windows manages the password | Anything that authenticates with Windows/Kerberos (SQL Server, SMB, AD) |
| Environment variable / registry value / config file in plain text | Anyone who can read the process, key or file | Nothing secret |
| DPAPI **LocalMachine** file + tight ACL | Any process on the host that can read the file, so the ACL is the control | Virtual accounts, multiple service identities on one host |
| DPAPI **CurrentUser** (`Export-Clixml`, `ConvertFrom-SecureString`) | Only that user, on that computer | gMSA or domain/local user accounts with a profile |
| SecretManagement + SecretStore | The user that created the store (CurrentUser only) | Scripts run as one account; module is feature complete, no new development |
| Credential Manager (generic) | Any process running as that user | Interactive tools; a poor fit for services |
| Service logon password (`Set-Service -Credential`) | SYSTEM and administrators (kept as an LSA secret) | Legacy services that need a named account; replace with gMSA |
| Azure Key Vault / AWS / GCP secret store | The workload identity with an access policy | Cloud and Arc-connected hosts, many servers |

The rule of thumb: **no password (gMSA or virtual account) first; then a cloud vault with a managed identity; on a
standalone host, a DPAPI-protected file behind an ACL.**

## 1. Prefer no secret at all

A virtual account (`NT SERVICE\AppSvc`) authenticates on the network as the computer account, and a gMSA gets a
240-byte password that the domain controllers rotate automatically (every 30 days by default, set when the account is
created). Neither has a password you can leak. Set it up with
[section 2 of the service-account page](windows-service-accounts-least-privilege.md#2-create-and-assign-the-account),
then grant the identity rights on the target (SQL login, share ACL) instead of storing a password.

Service accounts with a typed password are a target: the Service Control Manager keeps that password as an LSA secret,
and anyone with admin or SYSTEM on the host can dump it (MITRE T1003.004). Find them:

```powershell
# Services that run as a named user (not LocalSystem, LocalService, NetworkService or a virtual account)
Get-CimInstance Win32_Service |
    Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)' } |
    Select-Object Name, StartName, State | Sort-Object StartName
```

A `StartName` ending in `$` is a gMSA or MSA, which is fine. Anything else is a password to rotate (section 6) or,
better, to replace.

## 2. DPAPI machine scope + ACL (standalone host, any identity)

`LocalMachine` scope means any process on the computer can decrypt the blob. That is what makes it work for virtual
accounts and SYSTEM, and it is why the **file ACL** is the real access control. Encryption still keeps the secret
unreadable in backups, disk images and copies taken to another host. Optional entropy adds a second value the attacker
must also know (keep it in the program or its config, not next to the blob).

```powershell
# Run as an administrator. Windows PowerShell 5.1 needs: Add-Type -AssemblyName System.Security
$secretFile = 'C:\ProgramData\AppSvc\secrets\db-password.bin'
$entropy    = [Text.Encoding]::UTF8.GetBytes('AppSvc-db-v1')

$secure = Read-Host -AsSecureString -Prompt 'AppSvc DB password'
$plain  = [Text.Encoding]::UTF8.GetBytes([Net.NetworkCredential]::new('', $secure).Password)
try {
    $blob = [Security.Cryptography.ProtectedData]::Protect(
        $plain, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($secretFile, $blob)
} finally {
    [Array]::Clear($plain, 0, $plain.Length)
}

# Only SYSTEM, Administrators and the service read it (no inheritance from ProgramData)
icacls $secretFile /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' 'NT SERVICE\AppSvc:R'
```

The service decrypts it with the same scope and entropy:

```powershell
$blob  = [IO.File]::ReadAllBytes('C:\ProgramData\AppSvc\secrets\db-password.bin')
$bytes = [Security.Cryptography.ProtectedData]::Unprotect(
    $blob, [Text.Encoding]::UTF8.GetBytes('AppSvc-db-v1'), [Security.Cryptography.DataProtectionScope]::LocalMachine)
```

**Rotate:** write the new value over the same file (the ACL stays because the file is replaced in place), restart the
service, then change the value at the far end (database, API) and retire the old one.

## 3. DPAPI user scope (`Export-Clixml`) for a gMSA or user account

`Export-Clixml` and `ConvertFrom-SecureString` without `-Key` use DPAPI in the **current user** scope: only that user,
on that computer, can decrypt. A file you create in your own session therefore fails for the service. Create it **as
the service identity**. For a gMSA, a one-off scheduled task does that without knowing any password:

```powershell
# Run as an administrator. The task runs once as the gMSA and writes the file in its own DPAPI scope.
# Pass the value in through a short-lived admin-only file, deleted by the task (ACL it before writing).
$account = 'CONTOSO\gmsa-appsvc$'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -Command "$p = (Get-Content C:\ProgramData\AppSvc\secrets\incoming.txt -Raw).Trim(); ' +
    '(ConvertTo-SecureString $p -AsPlainText -Force) | Export-Clixml C:\ProgramData\AppSvc\secrets\api-token.xml; ' +
    'Remove-Item C:\ProgramData\AppSvc\secrets\incoming.txt"')
$principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Password
Register-ScheduledTask -TaskName 'AppSvc-SeedSecret' -Action $action -Principal $principal
Start-ScheduledTask -TaskName 'AppSvc-SeedSecret'
# Check api-token.xml exists and incoming.txt is gone, then:
Unregister-ScheduledTask -TaskName 'AppSvc-SeedSecret' -Confirm:$false
```

The service reads it back with `Import-Clixml` (a `SecureString`). The gMSA needs `Log on as a batch job` for the task
to run. For a virtual account, which cannot be a task principal, use machine scope (section 2) instead.

**Rotate:** repeat the seed task with the new value. If the account's profile or DPAPI master keys are lost (account
re-created, profile deleted), the old file cannot be decrypted at all; keep the source of truth elsewhere.

## 4. SecretManagement + SecretStore

`Microsoft.PowerShell.SecretManagement` is one set of commands (`Get-Secret`, `Set-Secret`) over pluggable vaults;
`Microsoft.PowerShell.SecretStore` is the local vault. Microsoft has declared both **feature complete**: security fixes
only, the repository is archived. They are still useful for scripts, but do not build a new service design on them.

- SecretStore is configured **per user**; `-Scope CurrentUser` is the only scope supported.
- Default authentication is `Password` with a 900-second unlock timeout. `Authentication None` is documented as "less
  secure" and meant for testing.
- For unattended use, Microsoft's own example keeps the store password in an `Export-Clixml` file, so the chain ends
  in DPAPI user scope (section 3) anyway.

```powershell
# Run in the context of the account that will read the secrets (for a gMSA, use the scheduled-task pattern above)
Install-PSResource Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore
Register-SecretVault -Name AppSvcStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

$storePassword = Read-Host -AsSecureString -Prompt 'Store password'
$storePassword | Export-Clixml -Path "$env:LOCALAPPDATA\AppSvc\store-password.xml"
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600 `
    -Interaction None -Password $storePassword -Confirm:$false

Set-Secret -Name AppSvcApiToken -Secret (Read-Host -AsSecureString -Prompt 'API token')

# In the job:
Unlock-SecretStore -Password (Import-Clixml "$env:LOCALAPPDATA\AppSvc\store-password.xml")
$token = Get-Secret -Name AppSvcApiToken           # SecureString; add -AsPlainText only at the point of use
```

Other extension vaults plug into the same `Get-Secret` call, for example Azure Key Vault through the `Az.KeyVault`
module, so scripts do not change when the backing store does.

**Rotate:** `Set-Secret` with the same name overwrites the value (use `-NoClobber` to refuse). Change the store
password with `Set-SecretStorePassword` and re-export the password file.

## 5. Credential Manager: know the limits

Credential Manager keeps **per-user** credentials. Two kinds matter:

- **Domain credentials** (`cmdkey /add:<target>`): used by Windows for SMB, RDP and similar logons. Only code inside
  the LSA can read the password; applications can only write it.
- **Generic credentials** (`cmdkey /generic:<target>`): **any process running as that user can read them** back in
  plain text through the Credential Manager API.

```cmd
:: List what the current user has stored (passwords are never shown)
cmdkey /list
:: Remove an entry that should not be there
cmdkey /delete:server01
```

For services this is a poor store: entries live in that account's profile, Windows ships no PowerShell cmdlets for
them, and `cmdkey /pass:` on the command line exposes the password to history and process auditing. Use it only when a
Windows component insists (a mapped drive for a scheduled task run as a user), and prefer a gMSA there too. Stored
credentials are also a common cause of account lockouts after a password change, see
[account lockout troubleshooting](../troubleshooting/account-lockout-troubleshooting.md).

## 6. Rotate a service logon password

If a service must run as a named account with a password, rotate it on the account and every service that uses it in
the same change window, or the next restart fails with a logon error (event 7000/7038).

```powershell
# 1. Where is this account used? Services and scheduled tasks on this host
$acct = 'CONTOSO\svc-appsvc'
Get-CimInstance Win32_Service | Where-Object StartName -eq $acct | Select-Object Name, State
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq $acct } | Select-Object TaskPath, TaskName

# 2. New password in AD (prompted), then on each service (PowerShell 6.0+ for -Credential)
$cred = Get-Credential -UserName $acct -Message 'New password for the service account'
Set-ADAccountPassword -Identity 'svc-appsvc' -Reset -NewPassword $cred.Password
Set-Service -Name AppSvc -Credential $cred
Restart-Service -Name AppSvc
```

Windows PowerShell 5.1 has no `-Credential` on `Set-Service`; use `sc.exe config AppSvc obj= CONTOSO\svc-appsvc
password= ...` only from an interactive prompt, since the password is visible in the command line. Better: move the
service to a gMSA and drop the password for good.

## Cloud secret stores

On a cloud VM or an Azure Arc-connected server, read the secret with the machine's own identity:

```powershell
# Azure (Az PowerShell): managed identity
Connect-AzAccount -Identity
Get-AzKeyVaultSecret -VaultName kv-app -Name appsvc-db -AsPlainText
```

```cmd
:: Azure CLI, AWS CLI and gcloud from the same host
az login --identity
az keyvault secret show --vault-name kv-app --name appsvc-db --query value -o tsv
aws secretsmanager get-secret-value --secret-id appsvc/db --query SecretString --output text
gcloud secrets versions access latest --secret=appsvc-db
```

Access control, rotation and audit for each: [Azure Key Vault](../../platforms/azure/keys-secrets.md) ·
[AWS keys & secrets](../../platforms/aws/keys-secrets.md) · [GCP keys & secrets](../../platforms/gcp/keys-secrets.md).

## 7. Who can read the secret?

```powershell
# ACL of the secrets folder and every file in it: expect SYSTEM, Administrators and the service only
Get-ChildItem C:\ProgramData\AppSvc\secrets -Force | ForEach-Object {
    [pscustomobject]@{ Path = $_.FullName; Access = (Get-Acl $_.FullName).AccessToString }
} | Format-List

# Which files could a broad group read? (Sysinternals AccessChk)
accesschk.exe -nobanner -s Users C:\ProgramData\AppSvc\secrets

# Plain-text secrets left in config files
Get-ChildItem C:\ProgramData, 'C:\Program Files' -Recurse -Include *.config, *.json, *.xml, *.ini -ErrorAction SilentlyContinue |
    Select-String -Pattern '(password|pwd|secret|token|apikey)\s*[=:"]' -List | Select-Object Path, LineNumber
```

Turn on object-access auditing for the secrets folder (SACL plus `auditpol /set /subcategory:"File System"
/success:enable`) so each read raises event 4663; see [audit policy](../../platforms/windows/audit-policy.md).

## Related

- [Credential rotation after a compromise](../incident-response/credential-rotation-after-compromise.md): the incident-response order for rotating these accounts and secrets
- [Service account audit script](../assurance/service-account-audit.md): finds services and tasks with typed passwords, stale passwords and gMSA retrievers
- [Windows service accounts with least privilege](windows-service-accounts-least-privilege.md) · [Linux service secrets](linux-service-secrets-storage.md)
- [AD Kerberos & LDAP hardening (gMSA rollout)](../hardening/ad-kerberos-ldap-hardening.md) · [Kerberoasting](../../fundamentals/concepts/kerberoasting.md)
- [Windows services](../../platforms/windows/services.md) · [Scheduled tasks](../../platforms/windows/scheduled-tasks.md) · [Windows files and permissions](../../platforms/windows/files-directories.md)
- [PowerShell and REST APIs (token handling)](../../languages/powershell/rest-apis.md) · [Certificate & PKI management](certificate-and-pki-management.md)

## Sources

- [DataProtectionScope](https://learn.microsoft.com/dotnet/api/system.security.cryptography.dataprotectionscope) (CurrentUser vs LocalMachine, "any process running on the computer") · [ProtectedData.Protect](https://learn.microsoft.com/dotnet/api/system.security.cryptography.protecteddata.protect)
- [ConvertFrom-SecureString](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/convertfrom-securestring) (DPAPI when no key) · [Export-Clixml](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-clixml)
- SecretManagement — [Get started with SecretStore](https://learn.microsoft.com/powershell/utility-modules/secretmanagement/get-started/using-secretstore) (feature-complete notice) · [Use SecretStore in automation](https://learn.microsoft.com/powershell/utility-modules/secretmanagement/how-to/using-secrets-in-automation) · [Set-SecretStoreConfiguration](https://learn.microsoft.com/powershell/module/microsoft.powershell.secretstore/set-secretstoreconfiguration) (CurrentUser only, Authentication None caution)
- [Kinds of credentials](https://learn.microsoft.com/windows/win32/secauthn/kinds-of-credentials) (domain vs generic, who can read) · [cmdkey](https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey)
- [Group Managed Service Accounts overview](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview) · [Set-Service](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-service) (-Credential, 6.0+) · [Set-ADAccountPassword](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountpassword) · [New-ScheduledTaskPrincipal](https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskprincipal)
- [Get-AzKeyVaultSecret](https://learn.microsoft.com/powershell/module/az.keyvault/get-azkeyvaultsecret) · [Sysinternals AccessChk](https://learn.microsoft.com/sysinternals/downloads/accesschk)
- MITRE ATT&CK — [T1003.004 LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) · [T1552.001 Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) · [T1555.004 Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
