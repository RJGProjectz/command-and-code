---
title: Linux CIS Benchmark Audit Tool (Ubuntu 24.04, RHEL 9)
type: tool
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Assurance
  - Administration
verified: true
last_verified: 2026-10-19
difficulty: intermediate
tags:
  - cis-benchmark
  - compliance
  - audit
  - sshd
  - sysctl
  - ndjson
aliases: [cis audit linux, cis ubuntu 24.04 audit, cis rhel 9 audit, cis rocky 9 audit, cis almalinux audit, linux cis script, audit_cis_linux.sh, linux hardening audit, cis level 1 linux check]
---

# Linux CIS Benchmark Audit Tool (Ubuntu 24.04, RHEL 9)

`scripts/bash/audit_cis_linux.sh` audits a Linux server against a CIS distribution benchmark and returns
one result per recommendation with the **same schema as the Windows tools**
([Windows 11](windows-11-cis-audit-tool.md), [Windows Server](windows-server-cis-audit-tool.md)): `Id`,
`Title`, `Level`, `Section`, `Status` (Pass / Fail / NotApplicable / Error), `Expected`, `Actual`, `Source`,
`Detail`. It is **read-only** and can also audit an offline file tree (a mounted disk image).

| Profile | Benchmark | Detected from `/etc/os-release` |
| :--- | :--- | :--- |
| `ubuntu2404` | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 (server profile) | `ID=ubuntu`, `VERSION_ID=24.04` |
| `rhel9` | CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 (server profile) | `ID` rhel, rocky, almalinux, ol, centos or `ID_LIKE` contains rhel; `VERSION_ID` 9.x |

macOS and other distributions are not covered yet. IDs, titles and levels were checked against the
open [ComplianceAsCode](https://github.com/ComplianceAsCode/content) control files for exactly these
benchmark versions; only IDs and titles are used, no CIS text.

!!! warning "Before you run anything"
    Run it with `sudo`: without root, `/etc/shadow`, `grub.cfg` and `sshd -T` are unreadable and those
    checks report **Error**. Nothing is changed in `--env Test` or `Prod`.

## What it checks

| Area | Recommendations (Ubuntu / RHEL IDs) | How |
| :--- | :--- | :--- |
| Kernel modules | 1.1.1.1–1.1.1.5, squashfs (L2), usb-storage (1.1.1.9 / 1.1.1.8) | Not loaded (`/proc/modules`), and either not on disk or `install <mod> /bin/false` + `blacklist <mod>` in `modprobe.d` |
| Mounts | 1.1.2.1.x `/tmp`, 1.1.2.2.x `/dev/shm`, 1.1.2.5.2–4 `/var/tmp` | `/proc/mounts`; option checks are NotApplicable when the path is not a separate mount |
| MAC | Ubuntu 1.3.1.2 AppArmor on the kernel line; RHEL 1.3.1.2 no `selinux=0`/`enforcing=0`, 1.3.1.4 not disabled, 1.3.1.5 enforcing (L2) | `grub.cfg`, BLS entries in `/boot/loader/entries`, `/etc/selinux/config`, `/sys/fs/selinux/enforce` |
| Boot | 1.4.2 bootloader config | `/boot/grub/grub.cfg` / `/boot/grub2/grub.cfg` mode ≤ 0600, owner root |
| Process hardening | 1.5.1 ASLR, 1.5.2 ptrace; core dumps (Ubuntu 1.5.3 limits + `fs.suid_dumpable`; RHEL 1.5.3/1.5.4 `coredump.conf`) | sysctl, `limits.conf`/`limits.d`, `coredump.conf` + drop-ins |
| Network | 3.3.1–3.3.11 forwarding, redirects, source routing, martians, SYN cookies, IPv6 RA | Runtime `/proc/sys` **and** persisted value must match |
| SSH server | Ubuntu 5.1.x / RHEL 5.1.x: config mode, Banner, ClientAlive, DisableForwarding (L2), Hostbased, IgnoreRhosts, LoginGraceTime ≤ 60, LogLevel INFO/VERBOSE, MaxAuthTries ≤ 4, MaxSessions ≤ 10, MaxStartups ≤ 10:30:60, PermitEmptyPasswords, PermitRootLogin, PermitUserEnvironment, UsePAM | `sshd -T` when run as root on the live host; otherwise `sshd_config` with `Include`, global section only, OpenSSH defaults for unset keywords |
| Cron, accounts | 2.4.1.2 `/etc/crontab`; 5.4.2.1 only root has UID 0; 7.2.1 shadowed passwords; 7.2.2 no empty password | File modes and `/etc/passwd`, `/etc/shadow` |
| Account files | 7.1.1–7.1.8 passwd, group, shadow, gshadow and their `-` backups | ≤ 0644 root:root; shadow/gshadow ≤ 0640 root:root or root:shadow on Ubuntu, **0000** root:root on RHEL; missing backups are NotApplicable |
| Logging | auditd enabled and active (Ubuntu 6.2.1.2, RHEL 6.3.1.4, L2) | `systemctl` live; `*.wants/auditd.service` offline |

Not covered: manual recommendations, package installed/removed checks, firewall rule sets, PAM and
password-quality settings, the full auditd rule set. Use the guides in [Related](#related) for those.

## Run it

```bash
# Level 1, profile auto-detected, reports to a folder
sudo ./scripts/bash/audit_cis_linux.sh --level L1 --output-dir /var/tmp/cis

# Level 2 (includes every L1 recommendation), SSH section only, what is not passing
sudo ./scripts/bash/audit_cis_linux.sh --level L2 --id '5.1.*' | jq -c 'select(.result != "Pass") | {cis_id, expected, actual}'

# Offline: a disk image mounted read-only at /mnt/image
./scripts/bash/audit_cis_linux.sh --root /mnt/image --profile rhel9 --output-dir ./evidence

# Scheduled gate: exit 1 on drift, 2 when a check could not be evaluated
sudo ./scripts/bash/audit_cis_linux.sh --fail-on FailOrError --output-dir /var/log/cis > /dev/null
```

On an OS that does not match the profile the tool stops (exit 2); `--profile` with
`--skip-applicability` audits anyway and the results are indicative only. `--whatif` lists the sources
and reads none.

## Read the results

Statuses, score (`pass / (pass + fail)`) and exit codes (`--fail-on None|Fail|FailOrError` → 0/1/2) work as
in the [Windows tool](windows-11-cis-audit-tool.md#read-the-results). With `--output-dir` the files are
named `cis-<host>-<level>-<UTC time>`:

- **NDJSON** (also printed on stdout): GOLDEN_STANDARDS §4.7 fields plus `cis_id`, `title`, `section`,
  `expected`, `actual`, `source`, `detail`, `benchmark`, `benchmark_version`, `os_edition`, `os_build`,
  `elevated`, `profile`. Same field names as the Windows NDJSON, so one SIEM search covers both.
- **JSON**: `cc.cis.report/1` report with summary and the results array (Windows field names).
- **CSV**: `Id,Title,Level,Section,Status,Expected,Actual,Source,Detail`.

Points that differ from what you might expect:

- **sysctl** passes only when the runtime value and the persisted value agree. Persisted means the last
  assignment across `sysctl.d` files ordered by file name (a name in `/etc/sysctl.d` hides the same name in
  `/run` or `/usr/lib`), then `/etc/sysctl.conf`. A value set with `sysctl -w` only is a Fail: it is lost
  at reboot.
- **sshd** uses the **first** value for each keyword (`sshd_config(5)`), so a drop-in included at the top
  of `sshd_config` wins over a later line in the main file. `Match` blocks are not evaluated; offline,
  only the global section counts. On the live host as root, `sshd -T` gives the effective values.
- **IPv6** keys are skipped when the host has no IPv6 at runtime.

## Tests

`tests/python/test_audit_cis_linux.py` builds synthetic Ubuntu 24.04 and Rocky 9 trees in a temporary
folder and runs the script with `--root`: schema of every line, profile detection, kernel modules (install +
blacklist, loaded, dash/underscore names), mounts, sysctl runtime vs persisted and file order, sshd first
value / Include / Match / time units, accounts, SELinux in BLS entries, core dumps, level and ID filters,
JSON/NDJSON/CSV reports, exit codes, wrong-profile refusal and `--whatif`. File-mode assertions run on
Linux only (CI).

## Limits

- Doc-checked against the benchmark control lists and man pages; not yet run on a live Ubuntu 24.04 or
  RHEL 9 host. Expect to confirm the counts on the first run.
- Ownership checks need root-owned files: in the fixture tests they fail by design and are not asserted.
- One benchmark version per profile; a new CIS release needs the ID table in the script updated.

## Related

- [Linux posture scanners (Lynis, OpenSCAP, osquery)](../assurance/linux-posture-scanners.md): second opinion and how to reconcile oscap results with this tool
- [Linux CIS filesystems & services](linux-cis-filesystem-services.md)
- [Linux CIS auditd & telemetry baseline](linux-cis-auditd-logging.md)
- [Linux CIS access control, PAM & SSH](linux-cis-access-pam-ssh.md)
- [Linux security baseline](linux-security-baseline.md)
- [Windows Server CIS audit](windows-server-cis-audit-tool.md)

## Sources

- [CIS Benchmarks (Ubuntu Linux, Red Hat Enterprise Linux)](https://www.cisecurity.org/cis-benchmarks)
- [ComplianceAsCode control file: CIS Ubuntu 24.04 v1.0.0](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml)
- [ComplianceAsCode control file: CIS RHEL 9 v2.0.0](https://github.com/ComplianceAsCode/content/blob/master/products/rhel9/controls/cis_rhel9.yml)
- [sysctl.d(5)](https://man7.org/linux/man-pages/man5/sysctl.d.5.html)
- [sshd_config(5)](https://man.openbsd.org/sshd_config)
- [modprobe.d(5)](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [coredump.conf(5)](https://man7.org/linux/man-pages/man5/coredump.conf.5.html)
- [proc_mounts(5)](https://man7.org/linux/man-pages/man5/proc_mounts.5.html)
