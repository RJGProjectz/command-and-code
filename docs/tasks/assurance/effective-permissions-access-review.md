---
title: Effective Permissions and Access Review (Windows and Linux)
type: workflow
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, CMD, Bash]
tasks: [Assurance, Hardening, Administration]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [permissions, acl, ntfs, smb, service-dacl, suid, file-capabilities, access-review, recertification]
aliases: [who can read this file, who can write this folder, effective access, effective permissions, ntfs permissions report, icacls findsid, accesschk, share permissions audit, service permissions weak, sc sdshow decode, getfacl recursive, find suid sgid, world writable files, getcap, entitlement review, access recertification]
difficulty: intermediate
verified: true
last_verified: 2026-10-20
---

# Effective Permissions and Access Review (Windows and Linux)
> **Created**: 2026-10-20T02:40:00Z
> **Last Modified**: 2026-10-20T02:40:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Every command in sections 1-4 only reads. Changing an ACL (section 6) can lock out users or services:
> save the ACL first (`icacls /save`, `getfacl -R`) and test on a copy.

**Trigger:** "who can read or change this file, key, share or service?", a periodic access review, or a
finding such as a writable service binary.

**Goal:** a list of who has which access, with the risky grants marked, that an owner can recertify.

Background on accounts, groups and tokens: [Users, groups and privilege](../../fundamentals/concepts/users-groups-permissions.md).

## 1. Windows files and folders (NTFS)

```powershell
# One path: owner and every ACE (explicit and inherited)
Get-Acl -LiteralPath 'D:\Finance' | Select-Object Owner -ExpandProperty Access |
    Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited, InheritanceFlags

# A tree: only explicit (non-inherited) ACEs - where someone changed the permissions
Get-ChildItem -LiteralPath 'D:\Finance' -Recurse -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        $path = $_.FullName
        (Get-Acl -LiteralPath $path).Access | Where-Object { -not $_.IsInherited } |
            Select-Object @{ n = 'Path'; e = { $path } }, IdentityReference, FileSystemRights, AccessControlType
    } | Export-Csv .\finance-explicit-aces.csv -NoTypeInformation
```

```cmd
:: Files and folders whose DACL explicitly names a SID (Everyone; numeric SIDs need the leading *). /T recurse, /C continue, /Q quiet
icacls D:\Finance /findsid *S-1-1-0 /T /C /Q

:: Save the ACLs of a tree before any change (restore with icacls D:\ /restore finance-acl.txt)
icacls D:\Finance /save finance-acl.txt /T /C
```

Grants to flag: `Everyone` (S-1-1-0), `Authenticated Users` (S-1-5-11), `Users` (S-1-5-32-545) or
`Domain Users` with **Write**, **Modify** or **FullControl**; any non-admin with FullControl (it includes
changing the ACL and taking ownership).

**Effective** access is the sum of the user's and all their groups' allow ACEs minus deny ACEs. PowerShell
has no built-in for it; use the **Effective Access** tab (Properties → Security → Advanced) or AccessChk:

```cmd
:: Effective rights of one account on a path (Sysinternals AccessChk)
accesschk.exe -accepteula -nobanner "CONTOSO\jdoe" D:\Finance\Payroll.xlsx

:: Directories under C:\ that Users can write to (-u no errors, -w write only, -d directories only, -s recurse)
accesschk.exe -accepteula -nobanner -uwds Users C:\
```

## 2. Windows shares, registry keys and services

```powershell
# Share permissions (the share ACL), non-administrative shares only
Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | Get-SmbShareAccess |
    Format-Table Name, AccountName, AccessControlType, AccessRight
```

Network access is the **more restrictive** of the share ACL and the NTFS ACL on the share's `Path`; check
both (section 1 for NTFS). See [SMB](../../fundamentals/smb.md).

```powershell
# Registry key ACL, e.g. a service's configuration key
(Get-Acl -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler').Access |
    Format-Table IdentityReference, RegistryRights, AccessControlType, IsInherited
```

```cmd
:: Which services Authenticated Users can change (-c services, -w write, -v verbose)
accesschk.exe -accepteula -nobanner -uwcv "Authenticated Users" *
```

A service's own DACL (who may start, stop or reconfigure it) is in SDDL. `sc.exe sdshow` prints it; the
snippet below decodes it with the service access rights from the Win32 documentation:

```powershell
$service = 'Spooler'
$sddl = (sc.exe sdshow $service | Where-Object { $_ -like 'D:*' }) -join ''
$rights = [ordered]@{
    QueryConfig = 0x1; ChangeConfig = 0x2; QueryStatus = 0x4; EnumerateDependents = 0x8; Start = 0x10; Stop = 0x20
    PauseContinue = 0x40; Interrogate = 0x80; UserDefinedControl = 0x100; Delete = 0x10000; ReadControl = 0x20000
    WriteDac = 0x40000; WriteOwner = 0x80000
}
(ConvertFrom-SddlString -Sddl $sddl).RawDescriptor.DiscretionaryAcl | ForEach-Object {
    $mask = $_.AccessMask
    $sid = $_.SecurityIdentifier
    $name = try { $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $sid.Value }
    [PSCustomObject]@{
        Identity = $name
        Type     = $_.AceQualifier
        Rights   = ($rights.Keys | Where-Object { ($mask -band $rights[$_]) -eq $rights[$_] }) -join ', '
    }
} | Format-Table -Wrap
```

A non-admin identity with **ChangeConfig**, **WriteDac** or **WriteOwner** can point the service at its
own binary and run code as the service account (ATT&CK [T1574.011](https://attack.mitre.org/techniques/T1574/011/)
for the registry key, [T1574.010](https://attack.mitre.org/techniques/T1574/010/) for a writable service
binary). Check the binary's folder with section 1 as well. Granting one group start/stop only is shown in
[service accounts least privilege](../administration/windows-service-accounts-least-privilege.md).

## 3. Linux files, ACLs and special bits

```bash
# Who owns it, mode bits, and the permissions of every directory on the way (traversal needs x)
ls -l /srv/finance/payroll.csv
namei -l /srv/finance/payroll.csv

# POSIX ACLs: files that have entries beyond owner/group/other (-s skip base, -R recurse, -p absolute paths)
getfacl -R -s -p /srv/finance

# Save all ACLs of a tree before a change (restore: setfacl --restore=finance-acl.txt)
getfacl -R -p /srv/finance > finance-acl.txt

# Can this user actually read / write it? (runs the test as that user, groups included)
sudo -u jdoe test -r /srv/finance/payroll.csv && echo readable
sudo -u jdoe test -w /srv/finance/payroll.csv && echo writable
```

System-wide sweeps (`-xdev` stays on one filesystem; run per mount you care about):

```bash
# SUID and SGID executables - compare against a known-good list
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null

# World-writable files, and world-writable directories without the sticky bit
find / -xdev -type f -perm -0002 ! -path '/proc/*' 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null

# Files with no owner or group (left over from deleted accounts)
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# Everything one account owns, e.g. before removing it
find / -xdev -user jdoe 2>/dev/null

# File capabilities (root powers without SUID, e.g. cap_setuid, cap_dac_override)
getcap -r / 2>/dev/null
```

Flag: SUID copies of shells or interpreters ([T1548.001](https://attack.mitre.org/techniques/T1548/001/)),
`cap_setuid` / `cap_dac_override` / `cap_sys_admin` on anything outside the package baseline, writable
files in `/etc`, `/usr`, systemd unit directories or under a service's `ExecStart` path, and secret files
readable by other users (see [Linux service secrets storage](../administration/linux-service-secrets-storage.md)).
More command detail: [Linux users and permissions](../../platforms/linux/users-permissions.md).

## 4. Group membership behind the access

An ACE for a group is only as narrow as the group:

```powershell
Get-LocalGroupMember -Group 'Administrators'
Get-ADGroupMember -Identity 'Finance-RW' -Recursive | Select-Object Name, SamAccountName, objectClass   # RSAT AD module
whoami /groups    # the current token, including nested groups
```

```bash
getent group finance-rw
id jdoe
sudo -l -U jdoe   # what jdoe may run through sudo
```

## 5. Recertification CSV

Give each data owner one sheet: path, identity, access, inherited, and empty columns for the decision.

```powershell
Get-ChildItem -LiteralPath 'D:\Finance' -Recurse -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        $acl = Get-Acl -LiteralPath $_.FullName
        foreach ($ace in $acl.Access | Where-Object { -not $_.IsInherited }) {
            [PSCustomObject]@{
                Path = $_.FullName; Owner = $acl.Owner; Identity = $ace.IdentityReference
                Rights = $ace.FileSystemRights; Type = $ace.AccessControlType
                Decision = ''; ReviewedBy = ''; ReviewDate = ''
            }
        }
    } | Export-Csv .\recert-finance.csv -NoTypeInformation
```

```bash
{
    printf 'Path,Owner,Group,Mode,ACL,Decision,ReviewedBy,ReviewDate\n'
    find /srv/finance -xdev -print0 | while IFS= read -r -d '' path; do
        acl="$(getfacl -s -p -c "$path" 2>/dev/null | grep -v '^$' | paste -sd ';' -)"
        printf '"%s",%s,%s,%s,"%s",,,\n' "$path" "$(stat -c %U "$path")" "$(stat -c %G "$path")" "$(stat -c %a "$path")" "$acl"
    done
} > recert-finance.csv
```

Keep the signed-off sheet with the date; the next review diffs against it.

## 6. Fix what the review found

```powershell
# Remove one identity's explicit ACEs from a folder (save first - section 1)
icacls 'D:\Finance' /remove:g 'Everyone' /T /C
```

```bash
setfacl -x u:jdoe /srv/finance/payroll.csv   # remove one ACL entry
chmod o-w /path/to/world-writable-file
chmod u-s /usr/local/bin/oddtool             # drop SUID after confirming nothing needs it
setcap -r /usr/local/bin/oddtool             # remove file capabilities
```

Grant access to groups, not to users, and narrow broad groups instead of adding deny ACEs.

## Related

- [Windows service accounts least privilege](../administration/windows-service-accounts-least-privilege.md)
- [Linux service accounts least privilege](../administration/linux-service-accounts-least-privilege.md)
- [Local user and group administration](../administration/local-user-group-management.md)
- [Linux CIS access control, PAM & SSH](../hardening/linux-cis-access-pam-ssh.md)

## Sources

- [Get-Acl](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-acl)
- [icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls)
- [AccessChk](https://learn.microsoft.com/sysinternals/downloads/accesschk)
- [Get-SmbShareAccess](https://learn.microsoft.com/powershell/module/smbshare/get-smbshareaccess)
- [Service security and access rights](https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights)
- [ConvertFrom-SddlString](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertfrom-sddlstring)
- [getfacl(1)](https://man7.org/linux/man-pages/man1/getfacl.1.html), [setfacl(1)](https://man7.org/linux/man-pages/man1/setfacl.1.html), [find(1)](https://man7.org/linux/man-pages/man1/find.1.html), [getcap(8)](https://man7.org/linux/man-pages/man8/getcap.8.html), [namei(1)](https://man7.org/linux/man-pages/man1/namei.1.html)
