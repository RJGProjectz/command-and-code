---
title: Compare Files, Folders and Hashes
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
  - hash
  - get-filehash
  - sha256sum
  - diff
  - compare-object
  - baseline
  - integrity
aliases: [compare two files, compare folders, file hash, sha256 checksum, diff two directories, compare-object, fc command, verify download hash, file integrity baseline]
---

# Compare Files, Folders and Hashes

Is this the same file? What changed between two versions of a config? Which files differ between two folders, or
since last week? Hash, diff and baseline commands for Windows and Linux.

!!! warning "Before you run anything"
    Every command here only reads (the `robocopy` and `rsync` lines run in list-only / dry-run mode). Checked against
    Microsoft Learn and the coreutils, diffutils and rsync manuals (2026-10-13); the examples were run on test folders.

## 1. Hash a file

=== "PowerShell"

    ```powershell
    Get-FileHash -Path '.\setup.msi' -Algorithm SHA256
    (Get-FileHash '.\a.dll').Hash -eq (Get-FileHash '.\b.dll').Hash     # True when identical
    ```

=== "CMD"

    ```bat
    certutil -hashfile setup.msi SHA256
    ```

=== "Bash"

    ```bash
    sha256sum setup.tar.gz
    echo '<EXPECTED_SHA256>  setup.tar.gz' | sha256sum -c -   # prints "setup.tar.gz: OK" or FAILED
    ```

Compare against the hash the vendor publishes on its own site, not one printed next to the download link on a mirror.
MD5 and SHA-1 still spot accidental changes but not deliberate ones; use SHA-256.

## 2. What changed inside a text file

=== "PowerShell"

    ```powershell
    Compare-Object -ReferenceObject (Get-Content '.\old.conf') -DifferenceObject (Get-Content '.\new.conf')
    ```

=== "CMD"

    ```bat
    fc /n old.conf new.conf
    ```

=== "Bash"

    ```bash
    diff -u old.conf new.conf      # unified diff: - removed, + added
    cmp old.bin new.bin            # binary files: first differing byte
    ```

Example output (`Compare-Object`, test files, run locally):

```text
InputObject     SideIndicator
-----------     -------------
port=8443       =>
port=443        <=
```

`<=` lines exist only in the reference (old) file, `=>` only in the difference (new) file. `Compare-Object`
ignores line order; when order matters, use `fc` or `diff`.

## 3. Which files differ between two folders

=== "PowerShell"

    ```powershell
    function Get-TreeHash ([string]$Root) {
        $rootPath = (Resolve-Path $Root).Path
        Get-ChildItem -Path $rootPath -Recurse -File | ForEach-Object {
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($rootPath.Length).TrimStart('\')
                Hash         = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
            }
        }
    }
    Compare-Object (Get-TreeHash 'D:\Release\v1') (Get-TreeHash 'D:\Release\v2') -Property RelativePath, Hash |
        Sort-Object RelativePath
    ```

=== "CMD"

    ```bat
    rem /L lists only: nothing is copied or deleted
    robocopy D:\Release\v1 D:\Release\v2 /MIR /L /NJH /NJS /NDL /NP
    ```

=== "Bash"

    ```bash
    diff -rq /srv/release/v1 /srv/release/v2                 # names of files that differ or exist on one side
    rsync -rcn --delete --itemize-changes /srv/release/v1/ /srv/release/v2/   # -n dry run, -c compare by checksum
    ```

`robocopy` marks differences as `New File`, `*EXTRA File`, `Newer` or `Older`, and returns exit codes 1 to 7 when it
found differences: below 8 is not an error.

In the PowerShell result a changed file appears twice (once per side, different hash); a file present on one side
only appears once.

## 4. Baseline now, check later

Hash a folder that should not change (web root, scripts, `System32\drivers`) and compare later.

=== "PowerShell"

    ```powershell
    Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -File | Get-FileHash -Algorithm SHA256 |
        Select-Object Path, Hash | Export-Csv 'D:\Baselines\wwwroot-20261013.csv' -NoTypeInformation

    # Later: what changed, appeared or disappeared since the baseline
    $baseline = Import-Csv 'D:\Baselines\wwwroot-20261013.csv'
    $now = Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash
    Compare-Object $baseline $now -Property Path, Hash
    ```

=== "Bash"

    ```bash
    find /var/www -type f -exec sha256sum {} + | sort -k 2 > /root/baselines/www-20261013.sha256
    sha256sum --quiet -c /root/baselines/www-20261013.sha256   # prints only files that changed or vanished
    ```

`sha256sum -c` does not report **new** files; diff a fresh file list against the baseline for those:
`diff <(cut -c 67- /root/baselines/www-20261013.sha256) <(find /var/www -type f | sort)`.

Keep baselines off the host you are checking, or an attacker can update them too. For continuous monitoring use a
file integrity tool (Wazuh/OSSEC, AIDE, Defender for Endpoint) rather than a scheduled script.

## Related

- [Identify file types](identify-file-types.md)
- [Finding files & content discovery](file-search-discovery.md)
- [Write command output to files](save-command-output-to-file.md)

## Sources

- [Microsoft Learn — Get-FileHash](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash)
- [Microsoft Learn — Compare-Object](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/compare-object)
- [Microsoft Learn — robocopy](https://learn.microsoft.com/windows-server/administration/windows-commands/robocopy) · [fc](https://learn.microsoft.com/windows-server/administration/windows-commands/fc) · [certutil](https://learn.microsoft.com/windows-server/administration/windows-commands/certutil)
- [sha256sum(1)](https://man7.org/linux/man-pages/man1/sha256sum.1.html) · [diff(1)](https://man7.org/linux/man-pages/man1/diff.1.html) · [rsync(1)](https://man7.org/linux/man-pages/man1/rsync.1.html)
