---
title: Delegated Administration Without Full Admin (JEA, sudo, polkit)
type: workflow
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, Bash]
tasks: [Administration, Hardening]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [jea, just-enough-administration, sudo, sudoers, polkit, least-privilege, delegation, privileged-access]
aliases: [jea endpoint, just enough administration, role capability psrc, session configuration pssc, Register-PSSessionConfiguration, RunAsVirtualAccount, jea gmsa, help desk without admin rights, sudoers command allowlist, Cmnd_Alias, sudoedit, sudo noexec, sudo log_output, polkit rules, manage-units polkit, restart service without admin, delegate service restart]
difficulty: advanced
verified: true
last_verified: 2026-10-20
---

# Delegated Administration Without Full Admin (JEA, sudo, polkit)
> **Created**: 2026-10-20T03:00:00Z
> **Last Modified**: 2026-10-20T03:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Registering a JEA endpoint restarts WinRM; a broken sudoers file can lock everyone out of sudo. Test on
> a lab host, keep a root/admin session open while you change sudoers, and validate with
> `Test-PSSessionConfigurationFile` and `visudo -c` before you rely on it.

**Trigger:** an operator, help desk or automation account needs to do a few admin tasks (restart a
service, clear a print queue, read a log, edit one config file) and is being given full Administrator or
root to do it.

**Goal:** the account can do exactly those tasks, every action is logged with the real user's name, and
nothing else is reachable.

| Need | Windows | Linux |
| :--- | :--- | :--- |
| Start/stop one service only | Service DACL (`sc.exe sdset`), see [service accounts least privilege](windows-service-accounts-least-privilege.md#7-let-operators-start-and-stop-one-service-service-dacl) | polkit rule for `manage-units` or sudo allowlist, see [Linux service accounts](linux-service-accounts-least-privilege.md#7-let-people-manage-the-service-without-full-root) |
| A set of admin commands with fixed parameters | **JEA** endpoint (sections 1-4) | **sudo** command allowlist (section 5) |
| Edit one config file | JEA custom function | `sudoedit` |
| Desktop / D-Bus actions (units, NetworkManager, packages) | — | **polkit** rules (section 6) |

## 1. JEA: write the role capability (what may be run)

A role capability (`.psrc`) lists the visible cmdlets, functions and programs. It must sit in a
`RoleCapabilities` folder of a module on `$Env:PSModulePath`, in a folder only administrators can change.

```powershell
$module = Join-Path $Env:ProgramFiles 'WindowsPowerShell\Modules\ContosoJEA'
New-Item -ItemType Directory -Path (Join-Path $module 'RoleCapabilities') -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $module 'ContosoJEAFunctions.psm1') -Force | Out-Null
New-ModuleManifest -Path (Join-Path $module 'ContosoJEA.psd1') -RootModule 'ContosoJEAFunctions.psm1'

$capability = @{
    Path                    = Join-Path $module 'RoleCapabilities\PrintOperator.psrc'
    Author                  = 'RJGProjectz'
    Description             = 'Help desk: print spooler and queue only'
    VisibleCmdlets          = @(
        'Get-Service', 'Get-Printer', 'Get-PrintJob'
        @{ Name = 'Restart-Service'; Parameters = @{ Name = 'Name'; ValidateSet = @('Spooler') } }
        @{ Name = 'Remove-PrintJob'; Parameters = @{ Name = 'PrinterName' }, @{ Name = 'ID' } }
    )
    VisibleFunctions        = @('TabExpansion2', 'Get-SpoolerError')
    FunctionDefinitions     = @{
        Name        = 'Get-SpoolerError'
        ScriptBlock = {
            param([ValidateRange(1, 200)][int]$Newest = 50)
            Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PrintService/Admin' } -MaxEvents $Newest
        }
    }
}
New-PSRoleCapabilityFile @capability
```

Rules that keep the endpoint narrow (from the Microsoft JEA guidance):

- List commands by full name; no wildcards (`Get-*`) in `VisibleCmdlets`.
- Constrain parameters with `ValidateSet` or `ValidatePattern` (not both on one parameter; the pattern
  wins).
- Never expose commands that run code or grant rights: `Start-Process`, `Invoke-Expression`,
  `Invoke-Command`, `Invoke-Item`, `Invoke-CimMethod`, `Invoke-WmiMethod`, `New-Service`,
  `New-ScheduledTask`, `Register-ScheduledJob`, `Add-LocalGroupMember`, `Add-ADGroupMember`, `net.exe`.
- `VisibleExternalCommands` needs full paths, and an executable cannot be parameter-constrained: wrap it in
  a function instead.
- Custom functions run in **FullLanguage** and see every provider: never pass user input to
  `Invoke-Expression`, and validate every parameter.
- No providers are visible by default; adding `FileSystem` next to `Remove-Item` in another role lets
  users delete any file. Roles **merge** to the most permissive set.

## 2. JEA: write the session configuration (who, and as whom)

```powershell
$session = @{
    Path                      = 'C:\ProgramData\JEAConfiguration\PrintOperator.pssc'
    SessionType               = 'RestrictedRemoteServer'      # NoLanguage, no providers, minimal default commands
    RunAsVirtualAccount       = $true
    RunAsVirtualAccountGroups = 'Print Operators'           # local group: the virtual account is NOT a local admin
    TranscriptDirectory       = 'C:\ProgramData\JEAConfiguration\Transcripts'
    RoleDefinitions           = @{ 'CONTOSO\HelpDesk-Print' = @{ RoleCapabilities = 'PrintOperator' } }
    RequiredGroups            = @{ Or = 'CONTOSO\SmartcardLogon', 'CONTOSO\MFA-Logon' }   # optional extra condition
}
New-Item -ItemType Directory -Path (Split-Path $session.Path) -Force | Out-Null
New-PSSessionConfigurationFile @session
Test-PSSessionConfigurationFile -Path $session.Path      # must return True
```

Run-as identity:

| Option | Rights | Use when |
| :--- | :--- | :--- |
| `RunAsVirtualAccount` alone | Member of local **Administrators**; on a domain controller, **Domain Admins** | Only if the commands truly need admin; never on a DC if avoidable |
| `RunAsVirtualAccount` + `RunAsVirtualAccountGroups` | Only the listed **local** groups | Default choice when a built-in or custom local group has the rights |
| `GroupManagedServiceAccount = 'CONTOSO\jea-print$'` | What the gMSA was granted, also on the network | Commands must reach shares or other servers; actions are harder to tie to a user, so keep transcripts |

The transcript folder is written by LocalSystem: give standard users no access to it.

## 3. JEA: register, connect, check

```powershell
Register-PSSessionConfiguration -Name 'PrintOperator' -Path 'C:\ProgramData\JEAConfiguration\PrintOperator.pssc' -Force   # restarts WinRM

# As the help-desk user, from their workstation
Enter-PSSession -ComputerName PRN01 -ConfigurationName PrintOperator
Get-Command                         # only what the role allows
Restart-Service -Name Spooler       # allowed
Restart-Service -Name WinRM         # refused: not in the ValidateSet

# As an administrator: what can this user do on this endpoint?
Get-PSSessionCapability -ConfigurationName PrintOperator -Username 'CONTOSO\jdoe'
Get-PSSessionConfiguration -Name PrintOperator | Select-Object Name, Permission, RunAsVirtualAccount
```

To change role mapping or identity, `Unregister-PSSessionConfiguration -Name PrintOperator` and register
again; edits to the `.psrc` apply to new sessions immediately.

## 4. JEA: audit

- Transcripts in `TranscriptDirectory`: connecting user, run-as identity, every command.
- `Microsoft-Windows-PowerShell/Operational` event 4104 (script block logging, if enabled) and the WinRM
  operational log for connections.
- Review who can connect: `RoleDefinitions` groups, and the endpoint's `Permission` property above.
- Treat changes to the module folder, `.psrc` or `.pssc` files as privileged changes (file integrity
  monitoring); anyone who can edit a role capability can give themselves any command.

## 5. sudo: command allowlists done right

Put each delegation in its own drop-in and always edit with `visudo`:

```bash
sudo visudo -f /etc/sudoers.d/60-webops
```

```text
# /etc/sudoers.d/60-webops  (mode 0440; a file name with a dot or ending in ~ is ignored)
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults:%webops log_output

Cmnd_Alias WEB_CTL  = /usr/bin/systemctl reload nginx.service, /usr/bin/systemctl restart nginx.service
Cmnd_Alias WEB_TEST = /usr/sbin/nginx -t
Cmnd_Alias WEB_LOGS = /usr/bin/journalctl -u nginx.service --no-pager -n 200

%webops ALL=(root) WEB_CTL, WEB_TEST
%webops ALL=(root) NOEXEC: WEB_LOGS
%webops ALL=(root) sudoedit /etc/nginx/conf.d/*.conf
%deploy ALL=(appsvc) NOPASSWD: /opt/appsvc/bin/deploy.sh ""
```

```bash
sudo visudo -c                 # syntax of /etc/sudoers and every drop-in
sudo -l -U jdoe                # effective rules for one user
sudoreplay -l                  # sessions recorded by log_output
```

What each line does, and the traps:

- **Exact arguments.** A command listed with arguments allows exactly those; a command listed with no
  arguments allows **any** arguments; `""` allows none (the `deploy.sh` line). A `*` in arguments also
  matches spaces and further options, so `systemctl restart *` allows every unit.
- **Run as a non-root user** where possible: `(appsvc)` runs the deploy script as the service account.
- **No shell escapes.** Editors, pagers, `find`, `tar`, `awk`, `less`, `vi`, `systemctl status` (pager) as
  root can start a shell. `NOEXEC:` stops the command from executing further programs (platform limits
  in `sudoers(5)`); `sudoedit` lets the user edit a temporary copy as themselves.
- **Writable targets.** Never allow a script or binary the delegated group can write, or one in a writable
  directory.
- **Logging.** `use_pty` and a sudo log file are CIS recommendations on Ubuntu and RHEL; `log_output`
  records the session for `sudoreplay`.

Check sudo rules regularly: [Linux sudoers integrity](../assurance/linux-sudoers-integrity.md).

## 6. polkit: allow one action for one group

`systemctl`, NetworkManager, `pkcon` and other D-Bus services ask polkit whether an unprivileged user may
act. A JavaScript rule can answer **yes** for a group and a specific object, without sudo:

```javascript
// /etc/polkit-1/rules.d/60-webops-nginx.rules
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") == "nginx.service" &&
        subject.isInGroup("webops")) {
        var verb = action.lookup("verb");
        if (verb == "reload" || verb == "restart") {
            polkit.log("webops " + subject.user + " " + verb + " nginx.service");
            return polkit.Result.YES;
        }
    }
});
```

```bash
pkaction --verbose --action-id org.freedesktop.systemd1.manage-units   # action and its defaults
systemctl restart nginx.service                                       # as a webops member, no sudo
journalctl -u polkit --since -10min                                    # polkit.log lines and errors
```

- polkit reloads rule files when they change; a syntax error is logged by `polkitd` and the file is skipped.
- `.rules` (JavaScript) files are used by RHEL 9 and by Ubuntu since 23.10; older Ubuntu releases use
  `.pkla` files.
- Rules run in order of file name across `/etc/polkit-1/rules.d` and `/usr/share/polkit-1/rules.d`; the
  first rule that returns a result wins.
- Return `polkit.Result.AUTH_ADMIN_KEEP` instead of `YES` to require an admin password.

## 7. Verify and review

- [ ] The delegated account cannot become admin: try `Add-LocalGroupMember` in JEA, `sudo -i` and
      `sudo bash` on Linux; all must fail.
- [ ] Every allowed action leaves a record with the real user (JEA transcript, `/var/log/sudo.log`,
      `polkit.log`).
- [ ] Group membership for `RoleDefinitions`, `%webops` and polkit groups is part of the
      [access review](../assurance/effective-permissions-access-review.md).
- [ ] The `.psrc`/`.pssc` files, `/etc/sudoers.d` and `/etc/polkit-1/rules.d` are root/admin-only and
      monitored for changes.

## Related

- [Windows service accounts least privilege](windows-service-accounts-least-privilege.md)
- [Linux service accounts least privilege](linux-service-accounts-least-privilege.md)
- [Local user and group administration](local-user-group-management.md)
- [Users, groups and privilege](../../fundamentals/concepts/users-groups-permissions.md)

## Sources

- [JEA overview](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/overview)
- [JEA role capabilities](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/role-capabilities)
- [JEA session configurations](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/session-configurations)
- [Registering JEA configurations](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/register-jea)
- [Auditing and reporting on JEA](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/audit-and-report)
- [sudoers(5)](https://www.sudo.ws/docs/man/sudoers.man/), [visudo(8)](https://www.sudo.ws/docs/man/visudo.man/), [sudoreplay(8)](https://www.sudo.ws/docs/man/sudoreplay.man/)
- [polkit(8)](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html), [systemd D-Bus polkit actions](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)
