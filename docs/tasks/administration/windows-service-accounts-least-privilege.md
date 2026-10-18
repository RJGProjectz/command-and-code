---
title: Windows Service Accounts with Least Privilege
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
  - service accounts
  - least privilege
  - gmsa
  - virtual accounts
  - icacls
  - service dacl
  - user rights
  - private keys
aliases: [create service account windows, run service as non-admin, NT SERVICE account, virtual service account, gMSA service, managed service account, New-ADServiceAccount, Install-ADServiceAccount, give service account folder permissions, icacls grant service, registry key permissions service, sc sdset, let user restart service without admin, log on as a service right, deny interactive logon service account, certificate private key permissions service, service runs as LocalSystem]
---

# Windows Service Accounts with Least Privilege

*"The service runs as LocalSystem because the installer said so."* *"It needs a domain account, and the password has
not changed since 2017."* *"The helpdesk must restart one service without being an administrator."* This workflow picks
the right identity for a Windows service and gives it exactly the access it needs on files, folders, registry keys,
other services, certificate private keys and secrets — all from PowerShell or `cmd`.

!!! warning "Before you run anything"
    Changing a service's account, a folder's ACL or a service's security descriptor can stop the service or lock
    administrators out of it. Save the current state first (`icacls ... /save`, `sc.exe sdshow`, `secedit /export`),
    work on a test machine, and run from an elevated PowerShell. Commands are checked against Microsoft Learn and the
    built-in `sc.exe` help (Sources); they were not run against a live service for this page. The example service is
    `AppSvc`, the domain `CONTOSO` — replace both.

## 1. Pick the identity

| Identity | Example | Use it when | Password |
| --- | --- | --- | --- |
| **Virtual account** | `NT SERVICE\AppSvc` | One machine; access local files and keys. On the network it acts as the computer account (`CONTOSO\HOST01$`) | Managed by Windows |
| **gMSA** (group Managed Service Account) | `CONTOSO\gmsa-app$` | Needs a domain identity, Kerberos, or runs on several servers | 120 characters, rotated by AD (30 days by default) |
| **sMSA** (standalone MSA) | `CONTOSO\msa-app$` | Older setups tied to one server; prefer gMSA | Managed by AD |
| Local user | `HOST01\svc_appsvc` | Workgroup server and the app cannot use a virtual account | You manage it |
| Domain user | `CONTOSO\svc_appsvc` | Only when the app does not support gMSA | You manage it; a Kerberoasting target if it has an SPN |
| LocalService / NetworkService | built in | Low-privilege shared identities; give the service its own SID (section 6) | None |
| **LocalSystem** | built in | Avoid: full control of the machine | None |

Prefer, in order: virtual account → gMSA → anything else. Both of the first two remove passwords that a person must
store, type or rotate.

## 2. Create and assign the account

=== "Virtual account"

    ```powershell
    # The account name is always NT SERVICE\<service name>; no password
    sc.exe config AppSvc obj= "NT SERVICE\AppSvc"
    Restart-Service -Name AppSvc
    Get-CimInstance Win32_Service -Filter "Name='AppSvc'" | Select-Object Name, StartName, State
    sc.exe showsid AppSvc        # the SID you will see in ACLs
    ```

    ```text
    NAME: AppSvc
    SERVICE SID: S-1-5-80-2990291636-2492480023-3406908447-1039772757-2238903568
    STATUS: Inactive
    ```

    `showsid` computes the SID from any name (STATUS shows whether a running service uses it). `sc.exe` needs the space after `obj=`. The service SID is derived from the service name, so it is the same on every
    machine.

=== "gMSA (domain)"

    ```powershell
    # Once per forest: KDS root key (domain admin). Domain controllers can use it after replication.
    Add-KdsRootKey -EffectiveImmediately

    # Group of servers allowed to fetch the password
    New-ADGroup -Name 'AppSvc-Hosts' -GroupScope Global -GroupCategory Security
    Add-ADGroupMember -Identity 'AppSvc-Hosts' -Members 'HOST01$'

    New-ADServiceAccount -Name 'gmsa-app' -DNSHostName 'gmsa-app.contoso.com' `
        -PrincipalsAllowedToRetrieveManagedPassword 'AppSvc-Hosts'
    ```

    ```powershell
    # On HOST01 (after a reboot, or klist -li 0x3e7 purge, so the computer picks up its new group)
    Install-ADServiceAccount -Identity 'gmsa-app'
    Test-ADServiceAccount -Identity 'gmsa-app'          # True = this host can retrieve the password
    sc.exe config AppSvc obj= 'CONTOSO\gmsa-app$'       # trailing $; leave the password out
    Restart-Service -Name AppSvc
    ```

    The gMSA name must be unique in the forest, and the password interval can only be set at creation
    (`-ManagedPasswordIntervalInDays`). Scheduled tasks can also run as a gMSA:
    `New-ScheduledTaskPrincipal -UserId 'CONTOSO\gmsa-app$' -LogonType Password`.

=== "Local user (workgroup)"

    ```powershell
    $password = Read-Host -AsSecureString -Prompt 'Password for svc_appsvc (long, random)'
    New-LocalUser -Name 'svc_appsvc' -Password $password -PasswordNeverExpires `
        -UserMayNotChangePassword -Description 'AppSvc service account'
    net user svc_appsvc                     # check "Local Group Memberships": no Administrators

    # PowerShell 6+: Set-Service -Credential. Windows PowerShell 5.1: use services.msc or sc.exe config.
    $credential = Get-Credential -UserName "$env:COMPUTERNAME\svc_appsvc" -Message 'AppSvc service account'
    Set-Service -Name AppSvc -Credential $credential
    ```

    Never pass the password on a command line (`sc.exe config ... password= ...`): it lands in shell history and in
    process-creation logs (event 4688 with command line, Sysmon event 1).

## 3. Logon rights: allow "service", deny everything else

A service account needs **Log on as a service** (`SeServiceLogonRight`), directly or through a group in the list
(for virtual accounts, typically `NT SERVICE\ALL SERVICES`, SID `S-1-5-80-0` — confirm it in your export).
`services.msc` adds the right when you pick an account there; when you configure the service from a script, check the
export and add the gMSA, sMSA or user account yourself.
Then deny interactive and Remote Desktop logons so nobody can sign in with the account.

```powershell
# Export the current user rights (keep this file as your rollback)
secedit /export /cfg C:\Temp\rights-before.inf /areas USER_RIGHTS
Select-String -Path C:\Temp\rights-before.inf -Pattern '^Se(ServiceLogon|DenyInteractiveLogon|DenyRemoteInteractiveLogon)Right'

# SID of the account
$sid = ([System.Security.Principal.NTAccount]'CONTOSO\gmsa-app$').Translate(
          [System.Security.Principal.SecurityIdentifier]).Value
$sid
```

Edit a copy of the file so each line **keeps the existing entries** and adds `*<SID>` (the list replaces the old one
when imported), for example:

```text
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeServiceLogonRight = *S-1-5-80-0,*S-1-5-21-1111111111-2222222222-3333333333-4444
SeDenyInteractiveLogonRight = *S-1-5-32-546,*S-1-5-21-1111111111-2222222222-3333333333-4444
SeDenyRemoteInteractiveLogonRight = *S-1-5-21-1111111111-2222222222-3333333333-4444
```

```powershell
secedit /configure /db C:\Temp\rights.sdb /cfg C:\Temp\rights-new.inf /areas USER_RIGHTS
gpupdate /force
```

On domain members a GPO that sets the same right wins at the next refresh; set the rights in the GPO there (see
[User Rights Assignment](../hardening/windows-cis-user-rights-assignment.md)). The SIDs in the example are placeholders
except `S-1-5-80-0` (`NT SERVICE\ALL SERVICES`) and `S-1-5-32-546` (Guests).

## 4. Files and folders

Same model as on Linux: the service **reads** its program and config, **writes** only its data and logs, and never
writes its own binaries.

| Path (example) | Service gets | Why |
| --- | --- | --- |
| `C:\Program Files\AppSvc\` | Read & execute (inherited from `Users`) | Cannot replace its own code |
| `C:\ProgramData\AppSvc\config\` | Read | Config changed by admins only |
| `C:\ProgramData\AppSvc\data\`, `...\logs\` | Modify | The only writable places |

```powershell
$account = 'NT SERVICE\AppSvc'      # or 'CONTOSO\gmsa-app$'

# Save current ACLs first (restore with: icacls C:\ProgramData /restore C:\Temp\appsvc-acl.txt)
icacls C:\ProgramData\AppSvc /save C:\Temp\appsvc-acl.txt /t

New-Item -ItemType Directory -Force -Path C:\ProgramData\AppSvc\config, C:\ProgramData\AppSvc\data, C:\ProgramData\AppSvc\logs | Out-Null
icacls C:\ProgramData\AppSvc\config /grant:r "${account}:(OI)(CI)RX"
icacls C:\ProgramData\AppSvc\data   /grant:r "${account}:(OI)(CI)M"
icacls C:\ProgramData\AppSvc\logs   /grant:r "${account}:(OI)(CI)M"

# Secrets folder: no inheritance, only SYSTEM, Administrators and the service (read)
icacls C:\ProgramData\AppSvc\secrets /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "${account}:(OI)(CI)R"

icacls C:\ProgramData\AppSvc\data
```

- `(OI)(CI)` = applies to files and subfolders; `RX` read & execute, `M` modify (includes delete), `R` read, `F` full.
  `/grant:r` replaces earlier explicit grants for that account instead of adding to them.
- `/inheritance:r` removes inherited entries, so `Users` no longer reads the secrets folder. Grant SYSTEM and
  Administrators back in the same command or you lose access.
- `C:\ProgramData` subfolders inherit **Users: read** and **CREATOR OWNER** rights; `C:\Program Files` is writable only
  by administrators and TrustedInstaller. Keep it that way — a user-writable service folder is a privilege escalation
  ([T1574.010](https://attack.mitre.org/techniques/T1574/010/)).

PowerShell equivalent (useful in scripts that build the rule from variables):

```powershell
$path = 'C:\ProgramData\AppSvc\data'
$acl  = Get-Acl -Path $path
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            'NT SERVICE\AppSvc', 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -Path $path -AclObject $acl
(Get-Acl -Path $path).Access | Where-Object IdentityReference -like '*AppSvc*' |
    Select-Object IdentityReference, FileSystemRights, InheritanceFlags
```

## 5. Registry keys

```powershell
$key  = 'HKLM:\SOFTWARE\Contoso\AppSvc'
$acl  = Get-Acl -Path $key
$rule = [System.Security.AccessControl.RegistryAccessRule]::new(
            'NT SERVICE\AppSvc', 'ReadKey', 'ContainerInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -Path $key -AclObject $acl
(Get-Acl -Path $key).Access | Where-Object IdentityReference -like '*AppSvc*'
```

Do not give a service account write access to its own service key
(`HKLM:\SYSTEM\CurrentControlSet\Services\AppSvc`): whoever can change `ImagePath` there chooses what runs as that
account. Check it with `(Get-Acl HKLM:\SYSTEM\CurrentControlSet\Services\AppSvc).Access`.

## 6. Lock down the service itself

```powershell
# Give a LocalService/NetworkService service its own SID, so ACLs can name NT SERVICE\AppSvc
sc.exe sidtype AppSvc unrestricted
# Stricter: write-restricted token - it can write only where its service SID is granted write
# sc.exe sidtype AppSvc restricted

# Drop privileges it does not need (applies at next start; the process gets only these)
sc.exe qprivs AppSvc
sc.exe privs AppSvc SeChangeNotifyPrivilege/SeCreateGlobalPrivilege
Restart-Service -Name AppSvc
```

`sc.exe privs` with no list means "everything the account may have". Check the running process afterwards with
Process Explorer or `whoami /priv` from a test build of the service; start with the vendor's documented list where
one exists.

## 7. Let operators start and stop one service (service DACL)

Who may start, stop or reconfigure a service is set by the service's own security descriptor, not by Administrators
membership. Grant a group start, stop and query on **one** service:

```powershell
$service = 'AppSvc'
$before  = (sc.exe sdshow $service | Where-Object { $_ }) -join ''
$before | Set-Content -Path "C:\Temp\$service-sddl-before.txt"      # rollback: sc.exe sdset AppSvc <that text>

$sid = ([System.Security.Principal.NTAccount]'CONTOSO\AppSvc-Ops').Translate(
          [System.Security.Principal.SecurityIdentifier]).Value
$ace = "(A;;RPWPLCRC;;;$sid)"           # RP start, WP stop, LC query status, RC read permissions

# Insert the ACE at the end of the DACL (before the S: audit section if there is one)
$after = if ($before -match 'S:\(') { $before -replace 'S:\(', "${ace}S:(" } else { $before + $ace }
$after
sc.exe sdset $service $after
# PowerShell 6+: Set-Service -Name $service -SecurityDescriptorSddl $after
```

| SDDL | Right | SDDL | Right |
| --- | --- | --- | --- |
| `CC` | query config | `RP` | start |
| `DC` | **change config** | `WP` | stop |
| `LC` | query status | `DT` | pause / continue |
| `SW` | list dependents | `LO` | interrogate |
| `RC` | read permissions | `CR` | user-defined control |
| `WD` / `WO` | change permissions / owner | `SD` | delete |

Never grant `DC`, `WD`, `WO` or `GA` to non-admins: change config lets them point the service at any program and run
it as the service account, often LocalSystem. Members of the group then run `Restart-Service AppSvc` or
`sc.exe stop AppSvc` without being administrators. For more than start/stop (read logs, run a fixed script),
use a JEA endpoint (planned, backlog WP-70).

## 8. Certificate private keys

A service that serves TLS or signs data needs **read** on the private key of its certificate in
`Cert:\LocalMachine\My`. The GUI way is certlm.msc → certificate → All Tasks → Manage Private Keys. From PowerShell,
find the key file and grant read:

```powershell
$thumbprint = '<THUMBPRINT>'
$cert = Get-Item -Path "Cert:\LocalMachine\My\$thumbprint"
$rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

if ($rsa -is [System.Security.Cryptography.RSACng]) {
    $keyFile = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$($rsa.Key.UniqueName)"
} else {
    $keyFile = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$($rsa.CspKeyContainerInfo.UniqueKeyContainerName)"
}
$keyFile
icacls $keyFile /grant "NT SERVICE\AppSvc:R"
icacls $keyFile
```

For ECDSA certificates use `GetECDsaPrivateKey` (CNG only, so the `Keys` folder). Grant read, never full control,
and only on the one key: the `MachineKeys` and `Keys` folders hold every machine key on the host.

## 9. Secrets the service needs

- **No password at all** is best: virtual account (local resources, computer account on the network) or gMSA
  (domain resources, SQL Server, file shares).
- Otherwise keep the secret in a file under the secrets folder from section 4 (service: read only), or in a vault the
  service reaches with its own identity (Azure Key Vault with a managed identity, for example).
- `Export-Clixml` and DPAPI user-scope secrets are tied to the profile that created them; a virtual account or gMSA
  must create its own copy, so prefer a machine-scope store or a vault for services. Details and rotation steps per
  store: [Store service secrets & keys on Windows](windows-service-secrets-storage.md).

## 10. Review

```powershell
# Every service with its account: look for LocalSystem services you did not expect and for user accounts
Get-CimInstance Win32_Service |
    Select-Object Name, StartName, StartMode, State, PathName |
    Sort-Object StartName | Format-Table -AutoSize

# Which gMSAs this host can use, and what the gMSA can do in AD
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames |
    Select-Object Name, PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames

# Domain user accounts with SPNs (Kerberoastable service accounts) - move them to gMSA
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet, ServicePrincipalName

# Effective access of the account on a folder (Sysinternals AccessChk)
accesschk.exe -accepteula -d "NT SERVICE\AppSvc" C:\ProgramData\AppSvc
accesschk.exe -accepteula -w -s "NT SERVICE\AppSvc" C:\       # everything it can write: should be its own folders only
```

Alert when a service account logs on interactively (event 4624 logon type 2 or 10 for the account) or when a
service is installed (event 7045 in System, 4697 in Security) or its start type changes (7040): see
[suspicious service investigation](../investigation/suspicious-service.md). Valid service accounts used by an
attacker are ATT&CK [T1078](https://attack.mitre.org/techniques/T1078/); weak service permissions are
[T1574.011](https://attack.mitre.org/techniques/T1574/011/).

## Related

- [Linux service accounts with least privilege](linux-service-accounts-least-privilege.md)
- [Windows services](../../platforms/windows/services.md) · [Windows files and permissions](../../platforms/windows/files-directories.md) · [Windows users and groups](../../platforms/windows/users-groups.md)
- [AD Kerberos & LDAP hardening (gMSA rollout)](../hardening/ad-kerberos-ldap-hardening.md) · [Kerberoasting](../../fundamentals/concepts/kerberoasting.md)
- [User Rights Assignment (CIS)](../hardening/windows-cis-user-rights-assignment.md)
- [Local user & group management](local-user-group-management.md) · [Certificate & PKI management](certificate-and-pki-management.md)

## Sources

- [Microsoft Learn — Manage group Managed Service Accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts) (prerequisites, New-/Install-/Test-ADServiceAccount, forest-unique names, interval set at creation) · [Create the KDS root key](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key)
- [Microsoft Learn — Service accounts (virtual accounts, MSA)](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-service-accounts) · [Log on as a service](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/log-on-as-a-service)
- [Microsoft Learn — Service security and access rights](https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights) (rights, defaults, SERVICE_CHANGE_CONFIG warning) · [SDDL ACE strings](https://learn.microsoft.com/windows/win32/secauthz/ace-strings)
- [Set-Service](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-service) (-Credential and -SecurityDescriptorSddl, PowerShell 6.0+) · [New-LocalUser](https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/new-localuser) · [New-ScheduledTaskPrincipal](https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskprincipal)
- [icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls) · [secedit /configure](https://learn.microsoft.com/windows-server/administration/windows-commands/secedit-configure) · [sc.exe config](https://learn.microsoft.com/windows-server/administration/windows-commands/sc-config); `sc.exe sidtype`, `privs`, `qprivs`, `showsid`, `sdset` from the built-in `sc.exe` help (Windows 11)
- [Sysinternals AccessChk](https://learn.microsoft.com/sysinternals/downloads/accesschk)
- [RSACertificateExtensions.GetRSAPrivateKey](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.rsacertificateextensions.getrsaprivatekey) · [CngKey.UniqueName](https://learn.microsoft.com/dotnet/api/system.security.cryptography.cngkey.uniquename)
- MITRE ATT&CK — [T1078](https://attack.mitre.org/techniques/T1078/) · [T1574.010](https://attack.mitre.org/techniques/T1574/010/) · [T1574.011](https://attack.mitre.org/techniques/T1574/011/)
