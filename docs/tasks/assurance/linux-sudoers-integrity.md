---
title: Assurance Check — Linux Sudoers File Integrity
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-12
difficulty: basic
tags:
  - assurance
  - linux
  - sudoers
  - integrity
---

# Assurance Check — Linux Sudoers File Integrity

Audits `/etc/sudoers` and drop-in configurations under `/etc/sudoers.d/` for unauthorized `NOPASSWD` privilege grants or syntax errors.

**Why:** one line in `sudoers` turns any user into root, and attackers add one to keep access ([T1548.003](https://attack.mitre.org/techniques/T1548/003/)). A syntax error is also a risk: it can lock every admin out of `sudo`. **Run as:** root; read-only.

## Bash verification script

```bash
#!/usr/bin/env bash
# Read-only sudoers audit. Prints PASS/FAIL/REVIEW lines.

# 1. Syntax of the main file and every drop-in
if visudo -c >/dev/null 2>&1; then
    echo "[PASS] sudoers syntax OK"
else
    echo "[FAIL] sudoers syntax error:"; visudo -c
fi

# 2. Ownership and permissions (want root:root 0440; drop-ins must not be writable by others)
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    perms=$(stat -c '%U:%G %a' "$f")
    [ "$perms" = "root:root 440" ] && echo "[PASS] $perms $f" || echo "[REVIEW] $perms $f"
done

# 3. Risky grants (comments ignored)
echo "=== NOPASSWD / !authenticate ==="
grep -rhEv '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -E 'NOPASSWD|!authenticate'

echo "=== Full root (ALL) grants ==="
grep -rhEv '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -E '\(ALL(:ALL)?\)\s+(NOPASSWD:\s*)?ALL'

echo "=== Members of the admin groups ==="
getent group sudo wheel admin 2>/dev/null

echo "=== Changed in the last 30 days ==="
find /etc/sudoers /etc/sudoers.d -type f -mtime -30 -ls 2>/dev/null
```

For one user's effective rights, including group and drop-in grants: `sudo -l -U <user>`.

## What to look for

| Pattern | Why it is risky |
| --- | --- |
| `NOPASSWD: ALL` for a person | Anyone with that session (or a stolen SSH key) is root without a password |
| `!authenticate` | Same effect as `NOPASSWD`, less obvious |
| Commands with shell escapes (`vi`, `less`, `find`, `awk`, `python`, `tar`) | Allowing one command still gives a root shell; see GTFOBins |
| Wildcards in arguments (`/bin/cat /var/log/*`) | `*` can match `../../etc/shadow` |
| Allowed script that the user can edit | The user edits the script, then runs it as root |
| Drop-in not in configuration management | Added by hand, possibly by an attacker |
| `#includedir` pointing somewhere unusual | Extra grants loaded from an unexpected path |

## Remediate

Always edit with `visudo` (or `visudo -f /etc/sudoers.d/<file>`), which refuses to save a broken file. Keep a root session open while you change sudo rules. Remove unexplained drop-ins only after saving a copy as evidence, then find out how they got there: `ausearch -k sudoers_changes -i` if the [auditd rules](../../platforms/linux/auditd.md) are in place.

## Related

- [Linux Audit Daemon (auditd)](../../platforms/linux/auditd.md)
- [Local User and Group Management](../administration/local-user-group-management.md)

## Sources

- [sudoers(5) manual](https://www.sudo.ws/docs/man/sudoers.man/)
- [visudo(8) manual](https://www.sudo.ws/docs/man/visudo.man/)
- [GTFOBins — sudo](https://gtfobins.github.io/#+sudo)
- [MITRE ATT&CK T1548.003](https://attack.mitre.org/techniques/T1548/003/)
