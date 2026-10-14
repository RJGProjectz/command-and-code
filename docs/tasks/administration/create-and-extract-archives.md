---
title: Create and Extract Archives (zip, tar)
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
  - Investigation
  - Forensics
verified: true
last_verified: 2026-10-13
difficulty: basic
tags:
  - zip
  - tar
  - compress-archive
  - expand-archive
  - archive
  - evidence collection
aliases: [zip a folder powershell, unzip powershell, tar on windows, tar czf, extract tar.gz, list zip contents, compress-archive hidden files]
---

# Create and Extract Archives (zip, tar)

Pack a folder to send or keep (logs, a triage collection), look inside an archive before you trust it, and extract
safely. Windows 10 1803 and later ship `tar.exe`, so the same `tar` commands work on Windows and Linux.

!!! warning "Before you run anything"
    Checked against Microsoft Learn and the bsdtar / GNU tar manuals (2026-10-13); every example was run locally
    with Windows PowerShell's `Compress-Archive` and the built-in `tar.exe` (bsdtar 3.8). Extracting **overwrites**
    files with the same name when you add `-Force` (PowerShell); extract into a new, empty folder.

## 1. Create an archive

=== "PowerShell"

    ```powershell
    Compress-Archive -Path 'C:\Logs\*' -DestinationPath 'C:\Temp\logs.zip'
    Compress-Archive -Path 'C:\Logs\*' -DestinationPath 'C:\Temp\logs.zip' -Update       # add/refresh files
    tar.exe -a -cf 'C:\Temp\logs.zip' -C 'C:\Logs' .                                       # zip via tar, keeps hidden files
    tar.exe -czf 'C:\Temp\logs.tgz' -C 'C:\Logs' .                                          # gzip-compressed tar
    ```

=== "Bash"

    ```bash
    tar -czf /tmp/logs.tgz -C /var/log/myapp .           # -C: archive paths relative to that folder
    tar -cJf /tmp/logs.tar.xz -C /var/log/myapp .         # xz: smaller, slower
    zip -r /tmp/logs.zip /var/log/myapp                    # if the zip package is installed
    ```

!!! danger "Compress-Archive skips hidden files"
    `Compress-Archive` silently leaves out hidden files and folders, and cannot store a single file over 2 GB
    ([Microsoft Learn](https://learn.microsoft.com/powershell/module/microsoft.powershell.archive/compress-archive)).
    Tested: a hidden `.hidden.cfg` was missing from the zip and present in the `tar.exe` archive. For evidence and
    full backups use `tar.exe`.

## 2. Look inside before extracting

=== "PowerShell"

    ```powershell
    tar.exe -tf 'C:\Temp\logs.zip'                     # works for .zip, .tar, .tgz
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::OpenRead('C:\Temp\logs.zip').Entries |
        Select-Object FullName, Length, LastWriteTime
    ```

=== "Bash"

    ```bash
    tar -tzvf /tmp/logs.tgz       # -t list, -v with sizes and dates
    unzip -l /tmp/logs.zip
    ```

Check the list for absolute paths (`/etc/...`, `C:\...`) and `..` components: a crafted archive can try to write
outside the target folder ("zip slip"). Current `tar` versions strip these by default; treat their presence as a
warning sign anyway.

## 3. Extract

=== "PowerShell"

    ```powershell
    Expand-Archive -Path 'C:\Temp\logs.zip' -DestinationPath 'C:\Temp\logs-extracted'
    New-Item -ItemType Directory -Path 'C:\Temp\logs-tgz' | Out-Null
    tar.exe -xzf 'C:\Temp\logs.tgz' -C 'C:\Temp\logs-tgz'
    ```

=== "Bash"

    ```bash
    mkdir -p /tmp/logs-extracted && tar -xzf /tmp/logs.tgz -C /tmp/logs-extracted
    tar -xzf /tmp/logs.tgz -C /tmp/logs-extracted ./logs/a.log      # one file only (use the path shown by -t)
    unzip /tmp/logs.zip -d /tmp/logs-zip
    ```

## 4. Collecting evidence: hash what you pack

```powershell
$case = 'C:\IR\CASE-042'
tar.exe -czf "$case.tgz" -C $case .
Get-FileHash "$case.tgz" -Algorithm SHA256 | Select-Object Hash | Out-File "$case.tgz.sha256.txt" -Encoding ascii
```

```bash
tar -czf /root/case-042.tgz -C /root/case-042 . && sha256sum /root/case-042.tgz > /root/case-042.tgz.sha256
```

Record the hash in the case notes before the archive leaves the host; the receiver checks it with `Get-FileHash` or
`sha256sum -c` ([Compare files and hashes](compare-files-and-folders.md)).

## Related

- [Write command output to files](save-command-output-to-file.md)
- [Remote file transfer](remote-file-transfer.md)
- [Backup and recovery](backup-and-recovery.md)

## Sources

- [Microsoft Learn — Compress-Archive](https://learn.microsoft.com/powershell/module/microsoft.powershell.archive/compress-archive) · [Expand-Archive](https://learn.microsoft.com/powershell/module/microsoft.powershell.archive/expand-archive)
- [Microsoft Command Line blog — tar and curl come to Windows](https://devblogs.microsoft.com/commandline/tar-and-curl-come-to-windows/)
- [bsdtar(1) — libarchive](https://man.freebsd.org/cgi/man.cgi?query=bsdtar) · [GNU tar manual](https://www.gnu.org/software/tar/manual/tar.html) · [unzip(1)](https://linux.die.net/man/1/unzip)
