---
title: Environment Variables and PATH
type: entry
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - CMD
  - Bash
tasks:
  - Administration
  - Troubleshooting
  - Hardening
verified: true
last_verified: 2026-10-14
difficulty: basic
tags:
  - environment variables
  - path
  - setx
  - export
  - systemd
  - cron
  - path interception
aliases: [add to path, set environment variable, setx truncated path, command not found after install, wrong version of python runs, environment variable not updating, export variable permanently, etc environment, cron job works manually but not in cron, sudo command not found]
---

# Environment Variables and PATH

*"It works in my shell but not in the service / cron job / new window."* *"The wrong `python` runs."* *"I added it to
PATH and nothing changed."* How environment variables are scoped and inherited, how to set them for a session or
permanently, and how to check PATH for problems an attacker could use.

!!! warning "Before you run anything"
    Reading variables is harmless. Changing machine-wide variables or the system PATH affects every new process on the
    host; keep a copy of the old value first. Windows commands and outputs on this page were run on Windows 11 with
    PowerShell 5.1 and 7.6 using test variables (2026-10-14); Linux behaviour is checked against the bash, cron,
    sudoers, pam_env, proc and systemd manuals.

## How inheritance works (the cause of most surprises)

A process gets a **copy** of its parent's environment when it starts. Changing a variable later, in the registry or in
a profile file, does not reach processes that are already running, or their future children.

- **Windows** writes Machine and User variables to the registry and notifies running programs; Explorer picks up the
  change, so programs you start from the Start menu or Explorer get it. A PowerShell window opened before you changed a
  User variable, and anything you start from it, still has the old values. In testing, a variable set with
  `[Environment]::SetEnvironmentVariable(..., 'User')` was not visible in a new `powershell` started from the existing
  window, only in a window opened from the Start menu. Services inherit the environment of the Service Control
  Manager, so a changed machine variable usually reaches services only after a restart of the computer.
- **Linux** has no registry: variables come from the parent, so a value exported in `~/.bashrc` exists only in
  processes started from a shell that read that file. Services, cron jobs and `sudo` commands each start from their
  own, much smaller environment (section 4).

## 1. See what is set

=== "PowerShell"

    ```powershell
    Get-ChildItem Env: | Sort-Object Name                    # this process
    $env:Path -split ';'                                     # PATH, one entry per line

    [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'   # what new processes get
    [Environment]::GetEnvironmentVariable('Path', 'User') -split ';'
    ```

=== "CMD"

    ```bat
    set
    echo %PATH%
    reg query "HKCU\Environment"
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    ```

=== "Bash"

    ```bash
    printenv | sort
    printf '%s\n' "$PATH" | tr ':' '\n'
    printenv APP_MODE        # one variable; exit code 1 if it is not set
    ```

User variables live in `HKCU\Environment`, machine variables in
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`. Windows combines them, Machine PATH first and then
User PATH.

## 2. Which program actually runs

=== "PowerShell"

    ```powershell
    Get-Command python -All | Select-Object CommandType, Source
    ```

=== "CMD"

    ```bat
    where python
    ```

=== "Bash"

    ```bash
    type -a python3          # aliases, functions and every match on PATH, in order
    command -v python3       # the one that runs
    hash -r                  # forget cached locations after changing PATH
    ```

Example output (Windows 11 with Python installed from python.org):

```text
CommandType Source
----------- ------
Application C:\Users\<USER>\AppData\Local\Microsoft\WindowsApps\python.exe
Application C:\Program Files\Python314\python.exe
```

The first match wins. Here a Microsoft Store *App execution alias* in `WindowsApps` comes before the real install, so
`python` may open the Store instead of running Python. Fix the order, or turn the alias off in *Settings → Apps →
Advanced app settings → App execution aliases*.

## 3. Set a variable

### For this session only

=== "PowerShell"

    ```powershell
    $env:APP_MODE = 'test'
    $env:Path = 'C:\Tools;' + $env:Path      # this window and its children only
    Remove-Item Env:\APP_MODE
    ```

=== "CMD"

    ```bat
    set APP_MODE=test
    set APP_MODE=
    ```

=== "Bash"

    ```bash
    export APP_MODE=test
    APP_MODE=test ./run.sh        # only for this one command
    unset APP_MODE
    ```

### Permanently on Windows

=== "PowerShell"

    ```powershell
    # User scope; Machine scope needs an elevated shell
    [Environment]::SetEnvironmentVariable('APP_MODE', 'test', 'User')

    # Delete: pass [NullString]::Value, not $null (see below)
    [Environment]::SetEnvironmentVariable('APP_MODE', [NullString]::Value, 'User')

    # Add a folder to the User PATH once, without duplicates
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($current -split ';' | Where-Object { $_ })
    if ($entries -notcontains 'C:\Tools') {
        [Environment]::SetEnvironmentVariable('Path', (($entries + 'C:\Tools') -join ';'), 'User')
    }
    ```

=== "CMD"

    ```bat
    setx APP_MODE test
    setx APP_MODE test /m
    ```

Tested behaviour to know before you change anything:

| What | Result |
| :--- | :--- |
| `SetEnvironmentVariable(name, $null, 'User')` in **PowerShell 7** | Variable **stays**, with an empty value. PowerShell passes `$null` as an empty string, and since .NET 9 an empty string no longer deletes. Windows PowerShell 5.1 deletes it. `[NullString]::Value` deletes in both |
| `SetEnvironmentVariable` on a value that contained `%USERPROFILE%` (REG_EXPAND_SZ) | Read returns the expanded text; writing it back stores **REG_SZ** with the expanded path. The `%...%` reference is gone for good |
| `setx` with a value over 1024 characters | *"WARNING: The data being saved is truncated to 1024 characters."* and it saves the cropped value |
| `setx` with a value containing `%NAME%` | Stored as REG_EXPAND_SZ, but Microsoft documents that `setx` on an existing variable replaces references with their expanded values |

Two consequences:

- **Never run `setx PATH "%PATH%;C:\Tools"`.** `%PATH%` in a command window is Machine + User PATH combined, so this
  copies the whole machine PATH into the user PATH, expands every reference, and crops the result at 1024 characters.
- **Edit the Machine PATH with the *Environment Variables* dialog** (`rundll32 sysdm.cpl,EditEnvironmentVariables`, or
  *System → Advanced system settings*), which keeps REG_EXPAND_SZ entries such as `%SystemRoot%\system32`. A script
  that reads and writes it through `[Environment]` flattens those entries. If you must script it, read the raw value
  and write it back as `ExpandString`:

```powershell
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$raw = (Get-Item -Path $key).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
$raw | Set-Content -Path "$env:TEMP\machine-path-backup.txt"
Set-ItemProperty -Path $key -Name 'Path' -Value ($raw.TrimEnd(';') + ';C:\Tools') -Type ExpandString -WhatIf
```

A direct registry write does not notify running programs (the `[Environment]` method sends `WM_SETTINGCHANGE`), so
sign out and back in before you test. To pick up the new PATH in the current PowerShell window:
`$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')`.

### Permanently on Linux

| Where | Applies to | Notes |
| :--- | :--- | :--- |
| `~/.bashrc` | Interactive non-login bash shells of that user | Terminal windows on most desktops; `export NAME=value` |
| `~/.bash_profile`, `~/.bash_login` or `~/.profile` | Login shells (SSH, console) of that user | Bash reads the first of the three that exists; many distributions source `~/.bashrc` from it |
| `/etc/profile.d/*.sh` | Login shells of all users | Read by `/etc/profile`; use a new file rather than editing `/etc/profile` |
| `/etc/environment` | Sessions that go through PAM (`pam_env`) | Simple `NAME=VALUE` lines, one per line; not a shell script, so no `export` |
| systemd unit `Environment=` / `EnvironmentFile=` | That service only | Services do not read shell profiles or `~/.bashrc` |
| Variable lines in a crontab (`NAME=value`) | That user's cron jobs | Cron sets `SHELL=/bin/sh`, `HOME` and `LOGNAME` itself and does not read profiles |

```bash
# A service: add a drop-in instead of editing the packaged unit
sudo systemctl edit nginx.service        # add:  [Service]  Environment="APP_MODE=test"
sudo systemctl restart nginx.service
systemctl cat nginx.service              # shows the unit plus drop-ins

# A cron job: set PATH at the top of the crontab
crontab -l | head -3                     # PATH=/usr/local/bin:/usr/bin:/bin
```

## 4. "Works in my shell, not in cron / sudo / the service"

- **cron** starts jobs with a minimal environment and a short PATH; anything installed in `/usr/local/bin`, `~/bin` or
  a virtual environment is not found. Set `PATH=` in the crontab or use full paths.
- **sudo** resets the environment by default (`env_reset`): it keeps a small list (`TERM`, `PATH`, `HOME`, `USER`, ...)
  and, when `secure_path` is set in sudoers, replaces your PATH with it. `sudo mytool` can fail with
  *command not found* while `mytool` works; use the full path, `sudo -i`, or add the folder to `secure_path`.
- **systemd services** get only the manager's environment plus their own `Environment=` lines.
- **A running process** keeps the environment it started with. To see what it actually has:

=== "PowerShell"

    ```powershell
    # No built-in cmdlet reads another process's environment.
    # Sysinternals Process Explorer: process Properties -> Environment tab.
    Get-CimInstance Win32_Process -Filter 'ProcessId = 1234' | Select-Object ProcessId, Name, CommandLine
    ```

=== "Bash"

    ```bash
    sudo cat /proc/1234/environ | tr '\0' '\n'
    sudo cat /proc/"$(systemctl show -p MainPID --value nginx.service)"/environ | tr '\0' '\n'
    ```

`/proc/PID/environ` shows the environment the program was started with; changes the process makes later are not
reflected.

## 5. Security: check PATH for hijack points

If a folder early in PATH is writable by ordinary users, anyone can drop a `python.exe`, `git.exe` or `ls` there and it
runs instead of the real one, including for administrators and services (MITRE ATT&CK T1574.007, Path Interception by
PATH Environment Variable). Missing folders in the machine PATH are a risk too when their parent is writable. Linux
adds two more: an empty entry (`::`, leading or trailing `:`) or `.` means "the current directory".

=== "PowerShell"

    ```powershell
    foreach ($dir in ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object { $_ })) {
        $expanded = [Environment]::ExpandEnvironmentVariables($dir)
        if (-not (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue)) { "MISSING  $expanded"; continue }
        $weak = (Get-Acl -LiteralPath $expanded).Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference -match '\\Users$|^Everyone$|\\Authenticated Users$' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl'
        }
        if ($weak) { "WRITABLE $expanded  ($(@($weak.IdentityReference) -join ', '))" }
    }
    ```

=== "Bash"

    ```bash
    printf '%s\n' "$PATH" | tr ':' '\n' | while IFS= read -r d; do
      case "$d" in
        ''|.) echo "CURRENT-DIR entry: '$d'" ;;
        *) if [ ! -d "$d" ]; then echo "MISSING  $d"
           elif [ -n "$(find "$d" -maxdepth 0 -perm -o+w)" ]; then echo "WORLD-WRITABLE $d"; fi ;;
      esac
    done
    ```

Example output (Windows; the first line is a real leftover from an uninstalled Java, the second came from a test
folder granted `Users:(M)`):

```text
MISSING  C:\Program Files (x86)\Common Files\Oracle\Java\javapath
WRITABLE C:\Users\<USER>\AppData\Local\Temp\cc_weak_dir  (BUILTIN\Users)
```

No `WRITABLE` lines is the healthy result. Run it elevated: a folder you cannot read (for example the SYSTEM
profile's `WindowsApps`) is also reported as `MISSING`. Remove missing entries, and move any user-writable folder out of the
machine PATH (or fix its permissions). The check looks at the machine PATH; folders in a user's own PATH are writable
by that user by design.

**Secrets:** environment variables are readable by the same user and by administrators/root (`/proc/PID/environ`,
Process Explorer), and are inherited by every child process. Prefer a secret store or a file with tight permissions;
see [cross-platform data handling](../../fundamentals/systems/cross-platform-data-handling.md).

## Related

- [File or port in use](../troubleshooting/file-or-port-in-use.md)
- [Scheduled jobs & Task Scheduler](scheduled-jobs-task-scheduler.md)
- [Package & software lifecycle](package-software-management.md)
- [Write command output to files](save-command-output-to-file.md)

## Sources

- [Microsoft Learn — Environment.SetEnvironmentVariable](https://learn.microsoft.com/dotnet/api/system.environment.setenvironmentvariable) (null/empty deletion, .NET 9 change, registry keys, WM_SETTINGCHANGE)
- [Microsoft Learn — setx](https://learn.microsoft.com/windows-server/administration/windows-commands/setx) (1024-character limit, expansion of references) · [about_Environment_Variables](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [GNU Bash manual — Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) · [crontab(5)](https://man7.org/linux/man-pages/man5/crontab.5.html) · [pam_env.conf(5)](https://man7.org/linux/man-pages/man5/pam_env.conf.5.html)
- [sudoers(5) — env_reset, secure_path](https://www.sudo.ws/docs/man/sudoers.man/) · [proc_pid_environ(5)](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html) · [systemd.exec(5)](https://man7.org/linux/man-pages/man5/systemd.exec.5.html) · [systemctl(1)](https://man7.org/linux/man-pages/man1/systemctl.1.html)
- [MITRE ATT&CK — T1574.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007/)
