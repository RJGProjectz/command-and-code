---
title: File or Port in Use — Find and Stop the Holder
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
  - Troubleshooting
  - Administration
verified: true
last_verified: 2026-10-14
difficulty: basic
tags:
  - port in use
  - locked file
  - handle
  - lsof
  - fuser
  - get-nettcpconnection
  - ss
aliases: [address already in use, port already in use, file is being used by another process, file locked, cannot delete file, device or resource busy, umount target is busy, text file busy, what is using port 8080, which process has this file open]
---

# File or Port in Use — Find and Stop the Holder

*"The process cannot access the file because it is being used by another process."* *"Address already in use."*
*"umount: target is busy."* Find which process holds the file, folder, mount or port, decide whether it should, and
only then stop it.

!!! warning "Before you run anything"
    Finding the holder is read-only. Stopping it is not: identify the process (and its service, parent and user)
    first, and prefer stopping the service over killing the process. Windows commands and outputs on this page were run
    on Windows 11 with test processes (2026-10-14); Linux commands are checked against the ss, lsof, fuser, proc and
    systemctl manuals.

## 1. Who is listening on a port

=== "PowerShell"

    ```powershell
    Get-NetTCPConnection -LocalPort 8080 -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess).ProcessName } }

    Get-NetUDPEndpoint -LocalPort 5353 | Select-Object LocalAddress, LocalPort, OwningProcess   # UDP has no state
    ```

=== "CMD"

    ```bat
    netstat -ano | findstr :8080
    tasklist /fi "PID eq 37064"
    ```

=== "Bash"

    ```bash
    sudo ss -ltnup 'sport = :8080'           # -l listening, -t TCP, -u UDP, -n numeric, -p process
    sudo lsof -nP -iTCP:8080 -sTCP:LISTEN
    sudo fuser -v 8080/tcp
    ```

Example output (Windows, a test web server on 127.0.0.1:8080):

```text
LocalAddress LocalPort OwningProcess Process
------------ --------- ------------- -------
127.0.0.1         8080         37064 python

  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       37064
```

Run the Linux commands with `sudo`: without it, `ss -p` and `lsof` cannot show processes owned by other users and the
process column stays empty.

## 2. Who has a file or folder open

=== "PowerShell"

    ```powershell
    # Sysinternals Handle: name match is a case-insensitive fragment of the path
    handle.exe -accepteula -nobanner 'C:\Reports\report.xlsx'

    # Is it locked at all? An exclusive open fails while another process holds it
    try {
        $stream = [System.IO.File]::Open('C:\Reports\report.xlsx', 'Open', 'Read', 'None')
        $stream.Close(); 'not locked'
    } catch { $_.Exception.Message }

    # On a file server: files opened by SMB clients (who, from where)
    Get-SmbOpenFile | Where-Object Path -like '*report.xlsx' |
        Select-Object FileId, ClientComputerName, ClientUserName, Path
    ```

=== "CMD"

    ```bat
    handle.exe -accepteula -nobanner C:\Reports\report.xlsx
    openfiles /query /fo table
    ```

=== "Bash"

    ```bash
    sudo lsof /srv/reports/report.xlsx
    sudo lsof +D /srv/reports            # everything open under a folder (slow on big trees)
    sudo fuser -vm /mnt/data             # who keeps a mount busy (umount: target is busy)
    sudo lsof +L1                        # deleted files still held open (disk full but du shows less)
    ```

Example output (Windows, a test process holding the file):

```text
python.exe         pid: 4992   type: File            E4: C:\Users\<USER>\AppData\Local\Temp\cc_lock_test\report.xlsx

Exception calling "Open" with "4" argument(s): "The process cannot access the file '...\report.xlsx' because it is being used by another process."
```

- **Handle** is Sysinternals (download from Microsoft, or `winget install Microsoft.Sysinternals.Handle`). Microsoft
  documents that it needs administrative rights; run it elevated to see other users' and services' processes.
  The GUI equivalents are Process Explorer (*Find → Find Handle or DLL*) and Resource Monitor (`resmon`, CPU tab,
  *Associated Handles* search box).
- **openfiles** shows files opened over the network by default. For local files it answers *"The system global flag
  'maintain objects list' needs to be enabled"*: that needs `openfiles /local on` and a restart, so use Handle instead.
- **Linux does not lock files against deletion.** `rm` on an open file succeeds; the space is freed only when the
  last process closes it, which is what `lsof +L1` finds (see [disk space emergency](disk-space-emergency.md)).
  Windows refuses the delete instead. Linux "busy" errors come from unmounting (`target is busy`) and from
  overwriting a running executable (`Text file busy`).

## 3. Identify the holder before you stop it

The PID alone is not enough: find the program path, the parent, the user and the service it belongs to.

=== "PowerShell"

    ```powershell
    Get-CimInstance Win32_Process -Filter 'ProcessId = 37064' |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

    Get-CimInstance Win32_Service -Filter 'ProcessId = 1940' | Select-Object Name, DisplayName, State
    ```

=== "CMD"

    ```bat
    tasklist /svc /fi "PID eq 1940"
    ```

=== "Bash"

    ```bash
    ps -o pid,ppid,user,lstart,cmd -p 1234
    systemctl status 1234                # shows the unit that PID belongs to
    ```

Example output (Windows; port 135 is held by a shared `svchost.exe`):

```text
Name         DisplayName                 State
----         -----------                 -----
RpcEptMapper RPC Endpoint Mapper         Running
RpcSs        Remote Procedure Call (RPC) Running
```

Things that catch people out:

- **Launchers and wrappers.** In the test above, `Start-Process` returned PID 36672 but the port belonged to PID 37064:
  a Python virtual-environment `python.exe` is a launcher that starts the real interpreter as a child. Look up the
  PID from the port or handle, not the one you started. Stopping only the parent can leave the child running.
- **PID 4 (`System`)** owns ports served by kernel drivers: SMB (445, 139) and HTTP.sys listeners such as IIS,
  WinRM (5985/5986) and other `http.sys` apps. `Stop-Process` cannot touch it; find the URL registration with
  `netsh http show servicestate` and stop the owning service.
- **"In use" but nobody is listening.** Windows reserves port ranges (Hyper-V, WSL, Docker):
  `netsh interface ipv4 show excludedportrange protocol=tcp`. A port inside a range cannot be bound even though
  `netstat` shows nothing on it.
- **Shared service hosts.** One `svchost.exe` can run several services; stop the service, not the host process.

## 4. Stop it

=== "PowerShell"

    ```powershell
    Stop-Service -Name 'Spooler' -WhatIf               # preferred when a service holds it
    Stop-Process -Id 37064 -WhatIf                     # remove -WhatIf when you are sure
    Close-SmbOpenFile -FileId 4415226383569 -WhatIf    # close one file a SMB client holds open
    ```

=== "CMD"

    ```bat
    taskkill /PID 37064
    taskkill /PID 37064 /T /F
    ```

=== "Bash"

    ```bash
    sudo systemctl stop nginx.service   # preferred when a unit holds it
    kill 1234                            # SIGTERM: lets the program clean up
    kill -9 1234                         # SIGKILL: last resort, no cleanup
    ```

`taskkill /T` also ends child processes, `/F` forces. `fuser -k` and `lsof -t | xargs kill` exist but kill every
process that matches, including ones you did not look at; list first, then stop by PID. Do not close individual
handles with `handle -c`: Microsoft warns that it can make the application or system unstable.

After stopping, retry the original action. If the holder comes straight back, something restarts it: a service
recovery action, a scheduled task, a systemd `Restart=` setting or a parent that respawns it.

## Security relevance

An unknown process listening on a port, or holding open files in user folders, is worth a closer look before you kill
it: kill it and the evidence (command line, network connections, open files) is gone. Capture the details from
section 3 first, then follow [suspicious process triage](../incident-response/suspicious-process.md).

## Related

- [Windows networking — find listening ports](../../platforms/windows/networking.md#find-listening-ports)
- [Linux networking — find listening ports](../../platforms/linux/networking.md#find-listening-ports)
- [Linux processes](../../platforms/linux/processes.md)
- [Disk space & inode emergency](disk-space-emergency.md)
- [Remote service restart](../administration/remote-service-restart.md)

## Sources

- [Microsoft Learn — Get-NetTCPConnection](https://learn.microsoft.com/powershell/module/nettcpip/get-nettcpconnection) · [Get-NetUDPEndpoint](https://learn.microsoft.com/powershell/module/nettcpip/get-netudpendpoint)
- [Microsoft Learn — Sysinternals Handle](https://learn.microsoft.com/sysinternals/downloads/handle) · [Process Explorer](https://learn.microsoft.com/sysinternals/downloads/process-explorer)
- [Microsoft Learn — Get-SmbOpenFile](https://learn.microsoft.com/powershell/module/smbshare/get-smbopenfile) · [Close-SmbOpenFile](https://learn.microsoft.com/powershell/module/smbshare/close-smbopenfile)
- [Microsoft Learn — netstat](https://learn.microsoft.com/windows-server/administration/windows-commands/netstat) · [tasklist](https://learn.microsoft.com/windows-server/administration/windows-commands/tasklist) · [taskkill](https://learn.microsoft.com/windows-server/administration/windows-commands/taskkill) · [openfiles](https://learn.microsoft.com/windows-server/administration/windows-commands/openfiles)
- [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html) · [lsof(8)](https://lsof.readthedocs.io/en/latest/manpage/) · [fuser(1)](https://man7.org/linux/man-pages/man1/fuser.1.html) · [systemctl(1)](https://man7.org/linux/man-pages/man1/systemctl.1.html)
