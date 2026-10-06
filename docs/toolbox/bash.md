---
title: Bash Toolbox
type: tool
platforms: [Linux]
languages: [Bash]
tasks: [Automation, Incident Response, Forensics, Investigation]
category: Tools
tags: [toolbox, scripts, triage, process tree, listening ports]
aliases: [bash scripts, linux triage script, linux collection script, process tree script]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Bash Toolbox

Reusable scripts in `scripts/bash/`. All are read-only, pass `shellcheck -S warning`, and depend only on tools present on mainstream distributions (`ss`, `ps`, `/proc`).

## get-listening-ports.sh

**Problem it solves:** `ss -lntup` packs the process into one hard-to-read column and never shows the binary path. This adds path and user and flags deleted or `/tmp`-resident binaries.

| | |
| --- | --- |
| Inputs | `-c` for CSV |
| Output | PROTO, LOCAL, PID, PROCESS, USER, EXE, FLAGS (`DELETED_BINARY`, `TEMP_PATH`) |
| Requirements | `ss` (iproute2). Root for other users' processes. |

```bash
sudo ./get-listening-ports.sh
sudo ./get-listening-ports.sh -c > listeners.csv
```

Related: [Linux networking](../platforms/linux/networking.md#find-listening-ports)

[Download get-listening-ports.sh](../../scripts/bash/get-listening-ports.sh)

??? abstract "Source"

    ```bash
    --8<-- "bash/get-listening-ports.sh"
    ```

## get-process-tree.sh

**Problem it solves:** ancestors **and** descendants of a PID with user, binary and full command line, without needing `pstree`.

```bash
./get-process-tree.sh 1234
```

Related: [Linux processes](../platforms/linux/processes.md#process-tree)

[Download get-process-tree.sh](../../scripts/bash/get-process-tree.sh)

??? abstract "Source"

    ```bash
    --8<-- "bash/get-process-tree.sh"
    ```

## linux-triage.sh

**Problem it solves:** consistent Linux first-response collection in one command.

| | |
| --- | --- |
| Inputs | `-o OUTPUT_DIR` (default `/var/tmp`) |
| Output | `triage-HOST-TIMESTAMP/` with one text file per artefact, `logs/` copies, `manifest-sha256.txt` |
| Collects | context, sockets, routes, resolver, firewall, processes (incl. deleted/tmp binaries), sessions, wtmp/btmp, crontabs, systemd timers/units, authorized_keys, effective sshd config, `ld.so.preload`, shell profiles, kernel modules, accounts, sudoers, SUID files, temp dirs, recent files, shell history, auth/syslog/audit logs, 48 h of journal |
| Behaviour | Missing tools are skipped and reported, never fatal. Output is created with `umask 077`. |

```bash
sudo ./linux-triage.sh -o /mnt/usb/cases
```

Related: [Endpoint Triage](../tasks/incident-response/endpoint-triage.md)

[Download linux-triage.sh](../../scripts/bash/linux-triage.sh)

??? abstract "Source"

    ```bash
    --8<-- "bash/linux-triage.sh"
    ```
