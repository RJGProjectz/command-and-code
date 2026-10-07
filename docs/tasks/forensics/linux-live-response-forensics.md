---
title: Linux Live Response and Forensic Artifact Extraction
type: workflow
platforms:
  - Linux
languages:
  - Bash
  - Python
tasks:
  - Forensics
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - linux
  - forensics
  - live-response
  - proc-fs
  - deleted-files
  - utmp
  - wtmp
  - bash-history
---

# Linux Live Response and Forensic Artifact Extraction

When responding to an active Linux intrusion, volatile system states, `/proc/` virtual filesystem structures, and session records reveal attacker implants, reverse shells, and deleted malware binaries.

---

## 1. Initial Volatile State Capture

Execute non-intrusive commands first, redirecting standard output to an external mount or staging directory.

```bash
# 1. Capture system identity, kernel, and boot parameters
mkdir -p /mnt/evidence/triage_$(date +%Y%m%d_%H%M%S)
cd /mnt/evidence/triage_*

uname -a > system_info.txt
cat /proc/version >> system_info.txt
cat /proc/cmdline >> system_info.txt
uptime >> system_info.txt

# 2. Capture active network sockets, listening ports, and routing tables
ss -tulpn > listening_sockets.txt
ss -tanp > active_connections.txt
ip route show > routing_table.txt
arp -an > arp_cache.txt

# 3. Process tree and environment parameters
ps auxwwf > process_tree.txt
lsof -Pni > open_files_network.txt
```

---

## 2. Forensic /proc/ Inode and Process Triage

On Linux, `/proc/` is a window into kernel memory. Even if an attacker unlinks (deletes) their binary from `/tmp`, the running executable remains intact inside `/proc/[PID]/`.

### Recovering Deleted Running Binaries (`(deleted)`)

```bash
# 1. Identify processes executing deleted binaries
ls -l /proc/*/exe 2>/dev/null | grep "\(deleted\)"

# Example output:
# /proc/2145/exe -> /tmp/c2_agent (deleted)

# 2. Carve and recover the deleted binary directly from the process memory file
cp /proc/2145/exe /mnt/evidence/recovered_c2_binary
chmod -x /mnt/evidence/recovered_c2_binary

# 3. Compute cryptographic hash of carved binary
sha256sum /mnt/evidence/recovered_c2_binary

# 4. Extract environment variables (C2 configuration, tokens, injected LD_PRELOAD)
strings /proc/2145/environ | sort > /mnt/evidence/pid_2145_environ.txt

# 5. Extract process working directory and open file descriptors
ls -la /proc/2145/cwd
ls -la /proc/2145/fd/
```

---

## 3. User Logon and Session Artifacts (`utmp`, `wtmp`, `btmp`)

Linux maintains binary logs of user sessions that survive shell exits:

```bash
# 1. Enumerate failed login attempts (Brute force & password spray)
# btmp binary log located at /var/log/btmp
lastb -F -a -i | head -n 30

# 2. Enumerate successful login and session history
# wtmp binary log located at /var/log/wtmp
last -F -a -i | head -n 30

# 3. Enumerate currently logged in interactive sessions
# utmp located in /var/run/utmp
who -a
w
```

---

## 4. Shell History and Anti-Forensics Analysis

Adversaries often unset `HISTFILE` or prepend commands with spaces to evade `.bash_history`.

```bash
# 1. Check all user shell history files with timestamps
for user_home in /root /home/*; do
    echo "=== History for $user_home ==="
    for hist in .bash_history .zsh_history .sh_history; do
        if [ -f "$user_home/$hist" ]; then
            ls -l "$user_home/$hist"
            # Display last 20 commands
            tail -n 20 "$user_home/$hist"
        fi
    done
done

# 2. Detect unlinked or hidden history files
find /home/ /root/ -maxdepth 2 -name ".*history*" -ls

# 3. Check for shell history evasion tricks in active processes
# Attackers often run: unset HISTFILE or export HISTSIZE=0
grep -E "HISTFILE|HISTSIZE|HISTFILESIZE" /proc/*/environ 2>/dev/null
```

---

## 5. Persistence & Cron Inspection

```bash
# 1. Enumerate all user crontabs
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null && echo "Crontab found for $user"
done

# 2. Inspect system cron directories and timers
ls -la /etc/cron* /var/spool/cron/crontabs/
systemctl list-timers --all

# 3. Check startup service unit files modified in the last 7 days
find /etc/systemd/system/ /lib/systemd/system/ -type f -mtime -7 -ls
```
