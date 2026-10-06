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
last_verified: 2026-10-06
difficulty: basic
tags:
  - assurance
  - linux
  - sudoers
  - integrity
---

# Assurance Check — Linux Sudoers File Integrity

Audits `/etc/sudoers` and drop-in configurations under `/etc/sudoers.d/` for unauthorized `NOPASSWD` privilege grants or syntax errors.

## Bash Verification Script

```bash
# 1. Syntax integrity check via visudo
visudo -c -f /etc/sudoers
if [ $? -ne 0 ]; then
    echo "[FAIL] Corrupt or unparseable /etc/sudoers detected!"
fi

# 2. Audit for unapproved NOPASSWD entries
echo "=== NOPASSWD Entries Audit ==="
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
