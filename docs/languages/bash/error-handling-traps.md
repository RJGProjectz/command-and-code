---
title: Bash Error Handling, Signals & Trap Handlers
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Automation
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - bash
  - error-handling
  - traps
  - signals
---

# Bash Error Handling, Signals & Trap Handlers

Techniques to intercept POSIX signals, catch execution errors, and cleanly unwind resources.

## Signal Trapping Example

```bash
#!/usr/bin/env bash
set -euo pipefail

# Log error location on unexpected command failure
error_handler() {
    local parent_lineno="$1"
    local message="$2"
    local code="${3:-1}"
    echo "[ERROR] Failure on line ${parent_lineno}: '${message}' (Exit Code: ${code})" >&2
}
trap 'error_handler ${LINENO} "$BASH_COMMAND" $?' ERR

# Clean exit on Ctrl+C (SIGINT) or SIGTERM
graceful_shutdown() {
    echo "\\n[INFO] Interrupt received. Shutting down cleanly..."
    exit 0
}
trap graceful_shutdown SIGINT SIGTERM
```
