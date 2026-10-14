---
title: Identify File Types (Not by Extension)
type: entry
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Administration
  - Investigation
  - Forensics
verified: true
last_verified: 2026-10-13
difficulty: intermediate
tags:
  - file type
  - magic bytes
  - file command
  - double extension
  - mark of the web
  - authenticode
aliases: [what type is this file, file magic bytes, find exe renamed as pdf, double extension, file command, mime type, zone.identifier]
---

# Identify File Types (Not by Extension)

An extension is only part of the name: `invoice.pdf` can be a Windows program. This page shows how to read what a
file really is from its first bytes, find files whose content does not match their name, and check where a file
came from and who signed it.

!!! warning "Before you run anything"
    Everything here only reads files. Checked against Microsoft Learn and the `file(1)` manual (2026-10-13); the
    examples were run on a test folder holding a copy of `notepad.exe` renamed to `invoice.pdf`. Do not open a
    suspect file to see what it is: read its bytes.

## 1. Magic bytes worth knowing

| First bytes (hex) | As text | File type |
| --- | --- | --- |
| `4D 5A` | `MZ` | Windows executable or DLL (PE) |
| `7F 45 4C 46` | `.ELF` | Linux executable or shared library |
| `25 50 44 46` | `%PDF` | PDF |
| `50 4B 03 04` | `PK..` | ZIP, and everything built on it: .docx, .xlsx, .jar, .apk |
| `D0 CF 11 E0` | | Old Office (.doc, .xls) and .msi |
| `1F 8B` | | gzip (.gz, .tgz) |
| `37 7A BC AF` | `7z..` | 7-Zip |
| `52 61 72 21` | `Rar!` | RAR |
| `89 50 4E 47` | `.PNG` | PNG |
| `FF D8 FF` | | JPEG |
| `23 21` | `#!` | Script with an interpreter line (shell, Python) |

## 2. Look at one file

=== "Linux"

    ```bash
    file invoice.pdf                    # invoice.pdf: PE32+ executable (GUI) x86-64, for MS Windows
    file --mime-type -b invoice.pdf     # application/vnd.microsoft.portable-executable
    xxd -l 16 invoice.pdf               # first 16 bytes in hex: 4d5a ... = MZ
    ```

=== "PowerShell"

    ```powershell
    Format-Hex -Path '.\invoice.pdf' | Select-Object -First 1     # first row: 4D 5A ... MZ

    # First 4 bytes as hex, works in Windows PowerShell 5.1 and PowerShell 7
    $stream = [System.IO.File]::OpenRead((Resolve-Path '.\invoice.pdf'))
    $buffer = New-Object byte[] 4
    $null = $stream.Read($buffer, 0, 4); $stream.Close()
    ($buffer | ForEach-Object { $_.ToString('X2') }) -join ' '    # 4D 5A 90 00
    ```

Older `file` versions report Windows executables as `application/x-dosexec`; newer ones (5.45) as
`application/vnd.microsoft.portable-executable`.

## 3. Find files whose content does not match the name

=== "PowerShell"

    ```powershell
    # Windows executables (MZ header) that are not named like one
    $exeNames = '.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.com', '.efi', '.mui'
    Get-ChildItem -Path 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -ge 2 -and $exeNames -notcontains $_.Extension.ToLower() } |
        ForEach-Object {
            try {
                $stream = [System.IO.File]::OpenRead($_.FullName)
                $head = New-Object byte[] 2
                $null = $stream.Read($head, 0, 2); $stream.Close()
                if ($head[0] -eq 0x4D -and $head[1] -eq 0x5A) { $_.FullName }
            } catch { }   # locked or unreadable file: skip
        }
    ```

=== "Linux"

    ```bash
    # ELF or Windows executables anywhere under /home and /tmp, whatever their name
    find /home /tmp -type f -size +1k -exec file --mime-type {} + 2>/dev/null |
        grep -E 'application/(x-executable|x-pie-executable|x-sharedlib|x-dosexec|vnd.microsoft.portable-executable)'
    ```

### Double extensions

Windows hides known extensions by default, so `invoice.pdf.exe` shows as `invoice.pdf`:

```powershell
Get-ChildItem -Path 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object Name -match '\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|com|bat|cmd|js|jse|vbs|vbe|hta|lnk|ps1|msi)$' |
    Select-Object FullName, Length, LastWriteTime
```

## 4. Where did it come from? (Mark of the Web)

Files downloaded by a browser or saved from email carry a `Zone.Identifier` alternate data stream on NTFS:

```powershell
Get-Content -Path '.\invoice.pdf' -Stream Zone.Identifier -ErrorAction SilentlyContinue
```

Example (illustrative values):

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://mail.example.com/
HostUrl=https://files.example.net/invoice.pdf
```

`ZoneId=3` is the Internet zone. No stream means the file was created locally, copied from a FAT/USB volume, or the
mark was removed (extracting from some archive tools drops it).

## 5. Who signed it, and what is it really called?

```powershell
Get-AuthenticodeSignature -FilePath '.\invoice.pdf' | Select-Object Status, @{ N = 'Signer'; E = { $_.SignerCertificate.Subject } }
(Get-Item '.\invoice.pdf').VersionInfo | Select-Object OriginalFilename, CompanyName, FileDescription
```

Example output (the renamed `notepad.exe` test file, run locally):

```text
Status Signer
------ ------
 Valid CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

OriginalFilename CompanyName           FileDescription
---------------- -----------           ---------------
NOTEPAD.EXE      Microsoft Corporation Notepad
```

`OriginalFilename` different from the name on disk means the file was renamed. The copy still shows `Valid`: Windows
binaries are often catalog-signed, and the catalog is looked up by the file's hash, not its name or path. A valid
Microsoft signature on a file called `invoice.pdf` in a Downloads folder is a renamed system binary, a common
living-off-the-land trick.
Hash it next: [Get-FileHash and comparisons](compare-files-and-folders.md).

## Related

- [Finding files & content discovery](file-search-discovery.md)
- [Windows files and directories](../../platforms/windows/files-directories.md)
- [Malware triage](../incident-response/malware-triage.md)

## Sources

- [file(1)](https://man7.org/linux/man-pages/man1/file.1.html) · [xxd(1)](https://man7.org/linux/man-pages/man1/xxd.1.html)
- [Microsoft Learn — Format-Hex](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/format-hex)
- [Microsoft Learn — Get-AuthenticodeSignature](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature)
- [Microsoft Learn — Get-Content -Stream (alternate data streams)](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-content)
- [Microsoft Learn — PE format (MS-DOS stub and signature)](https://learn.microsoft.com/windows/win32/debug/pe-format)
