---
title: Command Index — All Shells
type: reference
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, CMD, Bash]
tasks: [Administration, Troubleshooting, Investigation]
category: Reference
tags: [command index, commands, powershell, cmd, bash, zsh, cheat sheet, equivalents, a-z]
aliases: [command list, all commands, list of commands, powershell commands, cmd commands, bash commands, linux commands, windows commands, what is the command for, command lookup]
difficulty: basic
verified: true
last_verified: 2026-10-16
search:
  boost: 3
---

# Command Index — All Shells

One row per everyday job, with the command in **PowerShell**, **CMD** and **Bash** (zsh takes the Bash form unless
noted). Use the page search (`Ctrl+F`) or the site search for a command name; the last column links to the page with
options, output and caveats. For telemetry queries (KQL/SPL/S1QL) see [Cross-platform equivalents](equivalents.md).

"—" means the shell has no practical built-in; use the PowerShell column from CMD with `powershell -c "..."`.

## Help and discovery

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| Help for a command | `Get-Help Get-Process -Full` | `tasklist /?` | `man ps` · `ps --help` · `help cd` (builtins) | [PowerShell fundamentals](../languages/powershell/fundamentals.md) |
| Find a command by name | `Get-Command *service*` | `help` (built-in list) | `apropos service` · `compgen -c \| grep service` | [Windows CLI fundamentals](../languages/windows-cli/fundamentals.md) |
| Where is a program on PATH | `Get-Command python` | `where python` | `command -v python` · `type -a python` | [Environment variables & PATH](../tasks/administration/environment-variables-and-path.md) |
| Show aliases | `Get-Alias` | `doskey /macros` | `alias` | |
| What type of file | `Get-Item f \| Format-List *` | — | `file f` | [Identify file types](../tasks/administration/identify-file-types.md) |

## History

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| This session's history | `Get-History` | `doskey /history` | `history` | [Shell command history](../tasks/administration/shell-command-history.md) |
| All past sessions (file) | `Get-Content (Get-PSReadLineOption).HistorySavePath` | — (not saved) | `cat ~/.bash_history` · zsh `fc -l 1` | [Shell command history](../tasks/administration/shell-command-history.md) |
| Re-run entry *n* | `Invoke-History n` (`r n`) | `F9` then *n* | `!n` · `!!` (last) | |
| Search history interactively | `Ctrl+r` | `F8` (prefix) | `Ctrl+r` | |
| Record a whole session | `Start-Transcript` / `Stop-Transcript` | — | `script -a session.log` | |

## Navigation and files

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| Current directory | `Get-Location` (`pwd`) | `cd` | `pwd` | |
| Change directory | `Set-Location C:\Temp` (`cd`) | `cd /d D:\Temp` | `cd /tmp` | |
| List files incl. hidden | `Get-ChildItem -Force` (`ls`, `dir`) | `dir /a` | `ls -la` | [Windows files](../platforms/windows/files-directories.md) · [Linux filesystem](../platforms/linux/filesystem.md) |
| Copy | `Copy-Item a b -Recurse` | `copy` · `xcopy /e` · `robocopy src dst /e` | `cp -a a b` | |
| Move / rename | `Move-Item` · `Rename-Item` | `move` · `ren` | `mv` | |
| Delete | `Remove-Item x -Recurse -WhatIf` | `del` · `rmdir /s` | `rm -ri x` | |
| Make directory | `New-Item -ItemType Directory x` (`mkdir`) | `mkdir x` | `mkdir -p a/b` | |
| Read a file | `Get-Content f -Tail 50` | `type f` · `more f` | `cat f` · `tail -n 50 f` · `less f` | |
| Follow a growing file | `Get-Content f -Wait -Tail 20` | — | `tail -f f` | |
| Find files by name | `Get-ChildItem C:\ -Recurse -Filter *.log -EA SilentlyContinue` | `dir C:\*.log /s /b` | `find / -name '*.log' 2>/dev/null` | [File search & discovery](../tasks/administration/file-search-discovery.md) |
| Hash a file | `Get-FileHash f -Algorithm SHA256` | `certutil -hashfile f SHA256` | `sha256sum f` | |
| Compare files | `Compare-Object (gc a) (gc b)` | `fc a b` | `diff -u a b` | [Compare files & folders](../tasks/administration/compare-files-and-folders.md) |
| Zip / unzip | `Compress-Archive` · `Expand-Archive` | `tar -a -cf x.zip dir` · `tar -xf x.zip` | `tar -czf x.tgz dir` · `unzip x.zip` | [Archives](../tasks/administration/create-and-extract-archives.md) |
| Permissions | `Get-Acl f` | `icacls f` | `ls -l f` · `getfacl f` | [Users & permissions](../platforms/linux/users-permissions.md) |
| Disk usage by folder | `Get-ChildItem -Recurse \| Measure-Object Length -Sum` | `dir /s` | `du -sh * \| sort -h` | [Disk space audit](../tasks/administration/disk-space-audit.md) |

## Search text and output

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| Search text in files | `Select-String -Path *.log -Pattern error` | `findstr /s /i error *.log` | `grep -rin error .` | [Search logs by keyword](../tasks/administration/search-logs-by-keyword.md) |
| Filter command output | `... \| Select-String x` · `Where-Object` | `... \| findstr x` | `... \| grep x` | |
| Count lines | `(Get-Content f).Count` | `find /c /v "" f` | `wc -l f` | |
| Sort / unique | `Sort-Object -Unique` | `sort` | `sort \| uniq -c` | [Bash text processing](../languages/bash/text-processing.md) |
| Save output to a file | `... \| Out-File f` · `> f` | `> f` · `>> f` | `> f` · `>> f` · `\| tee f` | [Save output to a file](../tasks/administration/save-command-output-to-file.md) |
| Errors to the same file | `*> f` | `> f 2>&1` | `> f 2>&1` | [Save output to a file](../tasks/administration/save-command-output-to-file.md) |
| Show and save at once | `Tee-Object f` | — | `tee -a f` | |

## System and processes

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| OS version | `Get-CimInstance Win32_OperatingSystem` | `ver` · `systeminfo` | `cat /etc/os-release` · `uname -a` | [Windows](../platforms/windows/system-information.md) · [Linux](../platforms/linux/system-information.md) |
| Hostname | `$env:COMPUTERNAME` | `hostname` | `hostname` | |
| Uptime / last boot | `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` | `systeminfo \| find "Boot Time"` | `uptime` · `who -b` | |
| List processes | `Get-Process` | `tasklist` | `ps aux` · `top` | [Windows](../platforms/windows/processes.md) · [Linux](../platforms/linux/processes.md) |
| Process command line | `Get-CimInstance Win32_Process -Filter "ProcessId=1234"` | `wmic process where processid=1234 get commandline` (deprecated) | `ps -o pid,ppid,cmd -p 1234` | |
| Kill a process | `Stop-Process -Id 1234` | `taskkill /PID 1234 /F` | `kill 1234` · `kill -9 1234` | |
| Who holds a file / port | `Get-NetTCPConnection -LocalPort 443` | `netstat -ano \| findstr :443` | `ss -ltnp 'sport = :443'` · `lsof f` | [File or port in use](../tasks/troubleshooting/file-or-port-in-use.md) |
| Run in background | `Start-Job { ... }` · `Start-Process` | `start /b cmd` | `cmd &` · `nohup cmd &` | [Terminal sessions](../platforms/linux/terminal-sessions.md) |
| Keep running after disconnect | `Start-Process` / scheduled task | — | `tmux` · `screen` · `systemd-run` | [Terminal sessions](../platforms/linux/terminal-sessions.md) |
| Environment variables | `Get-ChildItem Env:` · `$env:PATH` | `set` · `echo %PATH%` | `env` · `echo "$PATH"` | [Environment variables & PATH](../tasks/administration/environment-variables-and-path.md) |
| Run as admin / root | `Start-Process pwsh -Verb RunAs` | `runas /user:Administrator cmd` | `sudo cmd` · `sudo -i` | |
| Reboot / shut down | `Restart-Computer` · `Stop-Computer` | `shutdown /r /t 0` · `shutdown /s /t 0` | `sudo systemctl reboot` · `sudo shutdown -h now` | |

## Services and scheduled jobs

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| List services | `Get-Service` | `sc query state= all` | `systemctl list-units --type=service` | [Windows](../platforms/windows/services.md) · [systemd](../platforms/linux/systemd.md) |
| Start / stop / restart | `Restart-Service x` | `sc stop x` · `net start x` | `sudo systemctl restart x` | |
| Startup type | `Set-Service x -StartupType Disabled` | `sc config x start= disabled` | `sudo systemctl disable --now x` | |
| Service logs | `Get-WinEvent -LogName System` | `wevtutil qe System /c:20 /rd:true /f:text` | `journalctl -u x -e` | [Windows event logs](../platforms/windows/event-logs.md) · [Linux logs](../platforms/linux/logs.md) |
| List scheduled jobs | `Get-ScheduledTask` | `schtasks /query /fo list /v` | `crontab -l` · `systemctl list-timers` | [Scheduled tasks](../platforms/windows/scheduled-tasks.md) · [Cron](../platforms/linux/cron.md) |
| Create a scheduled job | `Register-ScheduledTask` | `schtasks /create` | `crontab -e` · systemd timer | [Scheduled jobs](../tasks/administration/scheduled-jobs-task-scheduler.md) |

## Users and groups

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| Who am I | `whoami /all` | `whoami /all` | `id` · `whoami` | |
| Local users | `Get-LocalUser` | `net user` | `getent passwd` | [Local users & groups](../tasks/administration/local-user-group-management.md) |
| Group members | `Get-LocalGroupMember Administrators` | `net localgroup administrators` | `getent group sudo wheel` | [Windows users](../platforms/windows/users-groups.md) · [Linux users](../platforms/linux/users-permissions.md) |
| Logged-on users | `query user` | `query user` | `who` · `w` | |
| Change a password | `Set-LocalUser x -Password (Read-Host -AsSecureString)` | `net user x *` | `passwd x` | |

## Identity and directory (Active Directory / Entra ID)

Directory queries across every shell, plus the query-side (SIEM) equivalent. PowerShell uses the RSAT
`ActiveDirectory` module; `dsquery`/`dsget` are the legacy CMD tools; `ldapsearch` works from Linux.
Replace `DC=corp,DC=example` with your domain's base DN.

| Job | PowerShell (AD module) | CMD (net / dsquery) | Bash (LDAP) | More |
| :--- | :--- | :--- | :--- | :--- |
| My identity and my groups | `whoami /all` · `Get-ADPrincipalGroupMembership $env:USERNAME` | `whoami /groups` · `gpresult /r` | `id` | [Windows users & groups](../platforms/windows/users-groups.md) |
| Look up a domain user | `Get-ADUser jsmith -Properties *` | `net user jsmith /domain` · `dsquery user -samid jsmith` | `ldapsearch -x -b "DC=corp,DC=example" "(sAMAccountName=jsmith)"` | [AD domain management](../tasks/administration/active-directory-domain-management.md) |
| **Find users by wildcard name** | `Get-ADUser -Filter "Name -like '*smith*'" -Properties DisplayName,Mail` | `dsquery user -name "*smith*"` | `ldapsearch -x -b "DC=corp,DC=example" "(cn=*smith*)" cn mail` | |
| A user's **direct** groups | `(Get-ADUser jsmith -Properties MemberOf).MemberOf` | `net user jsmith /domain` (Group lines) | `ldapsearch -x -b "DC=corp,DC=example" "(sAMAccountName=jsmith)" memberOf` | |
| A user's **all / nested** groups | `Get-ADPrincipalGroupMembership jsmith \| Select-Object Name` | `dsget user "<userDN>" -memberof -expand` | nested match: `(memberOf:1.2.840.113556.1.4.1941:=<groupDN>)` | [User lifecycle](../tasks/administration/user-lifecycle-management.md) |
| Members of a group (recursive) | `Get-ADGroupMember "Domain Admins" -Recursive \| Select-Object Name,SamAccountName` | `net group "Domain Admins" /domain` · `dsget group "<groupDN>" -members -expand` | `ldapsearch -x -b "DC=corp,DC=example" "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=example)"` | |
| Enabled / disabled accounts | `Get-ADUser -Filter 'Enabled -eq $true'` · `... 'Enabled -eq $false'` | `dsquery user -disabled` | `(userAccountControl:1.2.840.113556.1.4.803:=2)` = disabled | |
| Stale accounts (no recent logon) | `Get-ADUser -Filter 'LastLogonDate -lt $cut' -Properties LastLogonDate` | `dsquery user -inactive 8` | — | [AD domain management](../tasks/administration/active-directory-domain-management.md) |
| Locked-out accounts | `Search-ADAccount -LockedOut` | — | — | |

**Query side (SIEM) — the same identity questions on your own logs:**
[Logons & Identity hunting (KQL)](../detection/kql/logon-identity.md) ·
[Brute-force / spray correlation (SPL)](../detection/spl/brute-force.md). For AD **attack-path**
enumeration (not just lookups), see [Active Directory Enumeration](../offensive/active-directory-enumeration.md).

## Networking

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| IP configuration | `Get-NetIPConfiguration` | `ipconfig /all` | `ip -br a` · `ip r` | [Adapters & IP](../tasks/administration/network-adapter-ip-configuration.md) |
| Ping | `Test-Connection host -Count 4` | `ping host` | `ping -c 4 host` | |
| Test a TCP port | `Test-NetConnection host -Port 443` | — | `nc -zv host 443` | [Windows networking](../platforms/windows/networking.md) · [Linux networking](../platforms/linux/networking.md) |
| Trace route | `Test-NetConnection host -TraceRoute` | `tracert host` | `traceroute host` · `tracepath host` | |
| DNS lookup | `Resolve-DnsName host` | `nslookup host` | `dig host` · `getent hosts host` | [DNS troubleshooting](../tasks/administration/dns-resolution-troubleshooting.md) |
| Flush DNS cache | `Clear-DnsClientCache` | `ipconfig /flushdns` | `resolvectl flush-caches` | |
| Listening ports | `Get-NetTCPConnection -State Listen` | `netstat -ano` | `ss -lntup` | |
| Firewall rules | `Get-NetFirewallRule -Enabled True` | `netsh advfirewall firewall show rule name=all` | `sudo nft list ruleset` · `sudo ufw status` | [Firewall & ports](../tasks/administration/firewall-port-management.md) |
| Download a file | `Invoke-WebRequest url -OutFile f` | `curl -o f url` | `curl -o f url` · `wget url` | |
| Copy to/from a remote host | `Copy-Item -ToSession` · `scp` | `scp` | `scp` · `rsync -av` | [Remote file transfer](../tasks/administration/remote-file-transfer.md) |
| Remote shell | `Enter-PSSession host` · `ssh user@host` | `ssh user@host` | `ssh user@host` | [WinRM & OpenSSH](../platforms/windows/winrm-openssh.md) · [SSH](../platforms/linux/ssh.md) |

## Disks, software and logs

| Job | PowerShell | CMD | Bash | More |
| :--- | :--- | :--- | :--- | :--- |
| Free space | `Get-Volume` · `Get-PSDrive -PSProvider FileSystem` | `fsutil volume diskfree C:` | `df -h` | [Disk space audit](../tasks/administration/disk-space-audit.md) |
| Disks and partitions | `Get-Disk` · `Get-Partition` | `diskpart` → `list disk` | `lsblk` · `sudo fdisk -l` | [Windows storage](../platforms/windows/storage-disks.md) · [Storage & LVM](../platforms/linux/storage-lvm.md) |
| Installed software | `Get-Package` · `winget list` | `winget list` | `dpkg -l` · `rpm -qa` | [Package management](../tasks/administration/package-software-management.md) |
| Install / update | `winget install x` · `winget upgrade --all` | `winget install x` | `sudo apt install x` · `sudo dnf install x` | [Linux packages](../platforms/linux/packages.md) |
| Recent errors in logs | `Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20` | `wevtutil qe System /q:"*[System[Level=2]]" /c:20 /rd:true /f:text` | `journalctl -p err -b` | [Windows event logs](../platforms/windows/event-logs.md) · [Linux logs](../platforms/linux/logs.md) |
| Registry value | `Get-ItemProperty HKLM:\...` | `reg query HKLM\...` | — (Linux keeps settings in `/etc`) | [Registry](../platforms/windows/registry.md) |

## Related

- [Cross-platform equivalents (endpoint commands and KQL/SPL/S1QL)](equivalents.md)
- [PowerShell admin one-liners](powershell-cheat-sheet.md)
- [Linux sysadmin speed dial](linux-cheat-sheet.md)
- [Sysadmin quick reference](sysadmin-cheat-sheet.md)
- [Toolbox](../toolbox/index.md)

## Sources

- [Windows commands reference](https://learn.microsoft.com/windows-server/administration/windows-commands/windows-commands)
- [PowerShell module browser](https://learn.microsoft.com/powershell/module/)
- [man7.org Linux man pages](https://man7.org/linux/man-pages/)
- [GNU Bash manual](https://www.gnu.org/software/bash/manual/bash.html)
