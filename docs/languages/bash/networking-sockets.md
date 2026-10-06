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
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - bash
  - networking
  - sockets
  - dev-tcp
---

# Bash Pure Networking & /dev/tcp Socket Mechanics

Bash includes native `/dev/tcp` and `/dev/udp` pseudo-devices, enabling port testing and HTTP transactions without installing external dependencies like `netcat` or `telnet`.

## 1. Fast Port Reachability Test

```bash
# Test if a TCP socket is open with a 3-second timeout
timeout 3 bash -c "</dev/tcp/10.0.0.1/443" && echo "Port 443 is OPEN" || echo "Port 443 is CLOSED"
```

## 2. Minimal HTTP GET in Pure Bash

```bash
exec 3<>/dev/tcp/example.com/80
echo -e "GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n" >&3
cat <&3
exec 3<&-
exec 3>&-
```
