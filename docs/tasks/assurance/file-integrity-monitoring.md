---
title: File Integrity Monitoring (AIDE, SACLs, Sysmon)
type: workflow
platforms: [Linux, Windows, Windows Server]
languages: [Bash, PowerShell]
tasks: [Assurance, Detection Engineering]
category: Workflow
security_domain: Detection
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [file-integrity-monitoring, fim, aide, sacl, object-access, sysmon, event-4663, ndjson, change-detection]
aliases: [aide --init, aide --check, aide.conf rules, aide database, file integrity monitoring linux, file integrity monitoring windows, event 4663, event 4670, auditpol file system, FileSystemAuditRule, sacl on secrets, sysmon event 11, sysmon event 23, sysmon event 26, FileCreate FileDelete, detect changes to service binaries, detect sshd_config change, fim ndjson report]
difficulty: intermediate
verified: true
last_verified: 2026-10-20
---

# File Integrity Monitoring (AIDE, SACLs, Sysmon)
> **Created**: 2026-10-20T18:00:00Z
> **Last Modified**: 2026-10-20T18:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> A broad AIDE rule or SACL on a busy folder floods the disk and the SIEM. Start with the short path list
> below, measure event volume on a lab host for a day, then widen. An AIDE baseline taken on a host that
> is already compromised records the attacker's files as "good".

**Trigger:** you need to know when keys, secrets, sudo/SSH config or service binaries change, and by whom.

**Goal:** a baseline of the files that matter, a daily or real-time alert on change, and one NDJSON
record per change that the SIEM can join with change tickets.

| Platform | What changed (state) | Who changed it (event) |
| :--- | :--- | :--- |
| Linux | AIDE database compare | auditd watch (`-w path -p wa`), see [auditd logging](../hardening/linux-cis-auditd-logging.md) |
| Windows | hash baseline (section 5) | SACL + **4663**, Sysmon **11 / 23 / 26** |

## 1. What to watch

Keep the list short and specific. These are the paths that the service-account, secret and SSH pages
in this KB tell you to lock down:

| Linux | Windows |
| :--- | :--- |
| `/etc/ssh/sshd_config*`, `/etc/ssh/*_ca.pub`, `/etc/ssh/auth_principals/` | `C:\ProgramData\ssh\sshd_config`, `administrators_authorized_keys` |
| `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/polkit-1/rules.d/` | JEA `RoleCapabilities\*.psrc`, `*.pssc` |
| `/etc/krb5.keytab`, `/etc/sssd/sssd.conf` | Service binaries: `C:\Program Files\<App>\*.exe`, `*.dll` |
| `/etc/credstore*/`, `/etc/<app>/secrets/`, `/etc/systemd/system/` | `C:\ProgramData\<App>\secrets\` (DPAPI blobs, cert keys) |
| `/usr/bin`, `/usr/sbin`, `/usr/lib/systemd/system` | `C:\Windows\System32\drivers\etc\hosts`, scheduled task XML (`C:\Windows\System32\Tasks`) |

See [Linux service secrets](../administration/linux-service-secrets-storage.md) and
[Windows service secrets](../administration/windows-service-secrets-storage.md) for the secret paths.

## 2. Linux: AIDE baseline and check

```bash
# RHEL 9 (config /etc/aide.conf)            Ubuntu 24.04 (config /etc/aide/aide.conf)
dnf install aide                             # apt install aide
aide --init                                  # aide --config /etc/aide/aide.conf --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
aide --check                                 # compare filesystem with the baseline
```

Add local rules in the config (RHEL) or a drop-in under `/etc/aide/aide.conf.d/` (Ubuntu):

```text
# Rule groups: p perms, i inode, n links, u user, g group, s size, m mtime, c ctime, sha512 content hash
KEYS = p+i+n+u+g+s+m+c+sha512+acl+xattrs+selinux
/etc/ssh/          KEYS
/etc/sudoers       KEYS
/etc/sudoers.d/    KEYS
/etc/krb5.keytab   KEYS
/etc/sssd/         KEYS
/etc/credstore/    KEYS
/etc/systemd/system/ KEYS
# Logs and caches change all the time; exclude with a negative rule
!/var/log/
!/var/cache/
```

- Selection lines (AIDE manual): `/path` is a regular expression on the full path, `=/path` matches
  only that entry (not below it), `!/path` excludes.
- `acl`, `xattrs` and `selinux` work only if your AIDE build has them; distribution builds do.
- Exit code of `aide --check` is a bit mask: `0` no change, `1` added, `2` removed, `4` changed; values
  of 14 and above are errors. Alert on any non-zero value.
- After an approved change, run `aide --update` and replace the database the same way as after `--init`.
- Store a copy of `aide.db.gz` and of `aide` itself off the host (or on read-only media); an attacker
  with root can rebuild the local database.

Run it daily (RHEL has no timer by default; Ubuntu's package ships `dailyaidecheck`):

```ini
# /etc/systemd/system/aide-check.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --check
# /etc/systemd/system/aide-check.timer
[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
```

### NDJSON change report from AIDE

`aide --check` prints a summary with one line per entry under "Added entries", "Removed entries" and
"Changed entries" (`f   ...  : /path`). This turns those lines into NDJSON for the SIEM:

```bash
aide --check 2>&1 | awk -v host="$(hostname -s)" -v ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
    /^Added entries:/   { change = "added";   next }
    /^Removed entries:/ { change = "removed"; next }
    /^Changed entries:/ { change = "changed"; next }
    /^-+$/ || /^$/      { next }
    /^Detailed information/ { change = ""; next }
    change != "" && match($0, /: \//) {
        path = substr($0, RSTART + 2); gsub(/\\/, "\\\\", path); gsub(/"/, "\\\"", path)
        printf "{\"timestamp\":\"%s\",\"host\":\"%s\",\"tool\":\"aide\",\"action\":\"fim.change\",\"change\":\"%s\",\"path\":\"%s\"}\n", ts, host, change, path
    }' >> /var/log/fim/aide-changes.ndjson
```

AIDE 0.18 and later (Ubuntu 24.04) can also write JSON directly with `report_format=json` on a
`report_url`; RHEL 9 ships AIDE 0.16, which has the plain report only.

For **who** made the change, add auditd watches on the same paths (`-w /etc/sudoers.d/ -p wa -k fim`)
and search with `ausearch -k fim -i`.

## 3. Windows: SACL and event 4663

Turn on the File System subcategory, then put audit entries (SACLs) on the watched paths only.

```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /get /subcategory:"File System"

$paths = @("$Env:ProgramData\ssh", "$Env:ProgramData\ContosoApp\secrets", "$Env:ProgramFiles\ContosoApp")
foreach ($path in $paths) {
    $acl = Get-Acl -LiteralPath $path -Audit
    $rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
        'Everyone',
        'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership',
        'ContainerInherit, ObjectInherit', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl -WhatIf      # remove -WhatIf after review
}
(Get-Acl -LiteralPath "$Env:ProgramData\ssh" -Audit).Audit | Format-Table IdentityReference, FileSystemRights, AuditFlags
```

- Audit writes, deletes and permission changes, not reads, except on secret files where a read by the
  wrong account matters (add `ReadData` for that folder only).
- Without the `auditpol` setting the SACL produces nothing; with GPO-managed audit policy set it in
  the GPO instead, see [advanced audit policy](../hardening/windows-cis-advanced-audit-policy.md).
- **4663** = an access was attempted on an object (fields `ObjectName`, `AccessList`/`AccessMask`,
  `ProcessName`, `SubjectUserName`). **4670** = permissions on an object were changed. **4656** = a
  handle was requested (noisier).

SACL basics and a registry example are on [Windows audit policy and SACLs](../../platforms/windows/audit-policy.md#4-system-access-control-lists-sacls-for-object-access).

## 4. Windows: Sysmon file events

Sysmon adds hashes and process context (Learn: Sysmon). Relevant event IDs:

| ID | Tag | Use |
| :--- | :--- | :--- |
| 11 | `FileCreate` | file created or overwritten (drops into program or secret folders) |
| 23 | `FileDelete` | delete, with a copy saved in `ArchiveDirectory` (default `C:\Sysmon`) |
| 26 | `FileDeleteDetected` | delete, logged only (no copy) — prefer this for volume |
| 29 | `FileExecutableDetected` | new PE file written |
| 2 | `FileCreateTime` | creation time changed (timestomping) |

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="fim" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="begin with">C:\ProgramData\ssh\</TargetFilename>
        <TargetFilename condition="begin with">C:\ProgramData\ContosoApp\secrets\</TargetFilename>
        <TargetFilename condition="begin with">C:\Program Files\ContosoApp\</TargetFilename>
      </FileCreate>
      <FileDeleteDetected onmatch="include">
        <TargetFilename condition="begin with">C:\ProgramData\ssh\</TargetFilename>
        <TargetFilename condition="begin with">C:\Program Files\ContosoApp\</TargetFilename>
      </FileDeleteDetected>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Merge these rules into your existing config (`sysmon64 -c config.xml`), see
[Deploy and tune Sysmon](../administration/sysmon-deployment-tuning.md). Use the schema version that
`sysmon64 -s` prints.

## 5. Windows: NDJSON change report

Collect 4663 and Sysmon events for the watched paths from the last day:

```powershell
$since = (Get-Date).AddDays(-1)
$watched = @('C:\ProgramData\ssh\', 'C:\ProgramData\ContosoApp\secrets\', 'C:\Program Files\ContosoApp\')
$out = Join-Path $Env:ProgramData 'FIM\fim-changes.ndjson'
New-Item -ItemType Directory -Path (Split-Path $out) -Force | Out-Null

$security = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663, 4670; StartTime = $since } -ErrorAction SilentlyContinue
$sysmon = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 11, 23, 26, 29; StartTime = $since } -ErrorAction SilentlyContinue

$records = @($security) + @($sysmon) | Where-Object { $null -ne $_ }
foreach ($record in $records) {
    $data = @{}
    foreach ($node in ([xml]$record.ToXml()).Event.EventData.Data) { $data[$node.Name] = $node.'#text' }
    $path = if ($data.ContainsKey('ObjectName')) { $data['ObjectName'] } else { $data['TargetFilename'] }
    if (-not ($watched | Where-Object { $path -like "$_*" })) { continue }
    [ordered]@{
        timestamp = $record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        host      = $Env:COMPUTERNAME
        tool      = 'fim-windows'
        action    = 'fim.change'
        event_id  = $record.Id
        path      = $path
        user      = if ($data.ContainsKey('SubjectUserName')) { "$($data['SubjectDomainName'])\$($data['SubjectUserName'])" } else { $data['User'] }
        process   = if ($data.ContainsKey('ProcessName')) { $data['ProcessName'] } else { $data['Image'] }
        access    = $data['AccessList']
        hash      = $data['Hashes']
    } | ConvertTo-Json -Compress | Add-Content -LiteralPath $out -Encoding utf8
}
```

For a state baseline like AIDE on Windows, hash the watched folders and compare with the last run,
see [compare files, folders and hashes](../administration/compare-files-and-folders.md).

## 6. Alert and tune

- Alert on: any AIDE change under `/etc/ssh`, `/etc/sudoers*`, keytab or credstore; 4663/Sysmon 11 on
  `administrators_authorized_keys` or a service binary outside a change window; 4670 on secret folders.
- Suppress package updates by joining with the package manager log (`dnf history`, `/var/log/apt/history.log`,
  Windows Installer event 11707) instead of excluding the paths.
- Review the watch list when a new service or secret is added (part of the
  [access review](effective-permissions-access-review.md)).

## 7. Verify

- [ ] `aide --check` exits 0 on a clean host and non-zero after `touch /etc/sudoers.d/test`.
- [ ] Writing a test file under each Windows watched folder gives a 4663 and a Sysmon 11 event.
- [ ] The NDJSON reports reach the SIEM and carry host, path, user and process.
- [ ] The AIDE database and binary have an off-host copy.

ATT&CK relevance: FIM catches **T1098.004** (SSH authorized keys), **T1543** (service binary or unit
changes), **T1548.003** (sudoers changes) and **T1070.006** (timestomping, Sysmon 2).

## Related

- [Linux posture scanners (Lynis, OpenSCAP, osquery)](linux-posture-scanners.md)
- [Linux CIS auditd logging](../hardening/linux-cis-auditd-logging.md)
- [Linux sudoers integrity](linux-sudoers-integrity.md)
- [Deploy and tune Sysmon](../administration/sysmon-deployment-tuning.md)
- [Run an SSH certificate authority](../administration/ssh-certificate-authority.md)
- [Join Linux to Active Directory](../administration/linux-active-directory-join-sssd.md)

## Sources

- [AIDE manual](https://aide.github.io/doc/)
- [Sysmon (Microsoft Learn)](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Audit File System (Microsoft Learn)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-system)
- [Event 4663](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663)
- [FileSystemAuditRule class](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemauditrule)
