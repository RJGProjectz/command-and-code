---
title: Linux Processes
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Troubleshooting, Forensics]
category: Processes
tags: [ps, proc, process tree, pid, deleted binary, lsof]
aliases: [find process by PID linux, ps aux, pstree, process command line linux, kill process linux]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Processes

## List processes

```bash
ps aux --sort=-%cpu | head -20
ps -eo pid,ppid,user,lstart,etime,cmd --sort=start_time
```

`lstart` is the full start timestamp; sorting by `start_time` puts the newest processes at the bottom.

## Find a process by PID

```bash
ps -o pid,ppid,user,lstart,cmd -p 1234
```

Everything about a process is under `/proc/<pid>`:

```bash
TARGET_PID=1234
sudo ls -l "/proc/$TARGET_PID/exe"                  # real binary path
sudo tr '\0' ' ' < "/proc/$TARGET_PID/cmdline"; echo  # full command line
sudo ls -l "/proc/$TARGET_PID/cwd"                  # working directory
sudo tr '\0' '\n' < "/proc/$TARGET_PID/environ"     # environment at start
grep -E '^(Name|PPid|Uid|Gid)' "/proc/$TARGET_PID/status"
```

`cmdline` and `environ` are NUL-separated — `tr` makes them readable.

## Process tree

```bash
pstree -p -a -s 1234       # ancestors and descendants with arguments
ps -ef --forest
```

Reusable tool: [`get-process-tree.sh`](../../toolbox/bash.md#get-process-treesh).

## Find processes by name

```bash
pgrep -a sshd
pgrep -u www-data -a .
```

`pgrep -a` prints the full command line.

## Processes running from deleted or temporary binaries

Malware frequently deletes its binary after starting. The kernel still shows it:

```bash
sudo ls -l /proc/*/exe 2>/dev/null | grep -E '\(deleted\)|/tmp/|/dev/shm/|/var/tmp/'
```

Recover a deleted binary for analysis while the process still runs:

```bash
sudo cp /proc/1234/exe /root/case/pid1234.bin
sha256sum /root/case/pid1234.bin
```

## Open files and network sockets of a process

```bash
sudo lsof -p 1234
sudo ls -l /proc/1234/fd
```

## Resource usage

```bash
top -b -n 1 | head -25
ps -o pid,pcpu,pmem,rss,cmd -p 1234
```

## Stop a process

```bash
kill 1234          # SIGTERM — ask nicely
kill -9 1234       # SIGKILL — cannot be caught
kill -STOP 1234    # freeze (keeps memory for collection), resume with kill -CONT
```

`kill -STOP` is useful in IR: it stops activity without destroying the process memory.

## Related

- [Suspicious Process workflow](../../tasks/incident-response/suspicious-process.md)
- [Windows processes](../windows/processes.md)
- [Linux networking](networking.md)

## Sources

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)
- [ps(1)](https://man7.org/linux/man-pages/man1/ps.1.html)
