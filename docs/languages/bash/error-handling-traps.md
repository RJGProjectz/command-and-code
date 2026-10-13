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
last_verified: 2026-10-12
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
set -Eeuo pipefail   # -E: ERR trap also fires inside functions and subshells

# Log error location on unexpected command failure
error_handler() {
    local code="$1"
    local parent_lineno="$2"
    local message="$3"
    echo "[ERROR] Failure on line ${parent_lineno}: '${message}' (Exit Code: ${code})" >&2
}
trap 'error_handler $? ${LINENO} "$BASH_COMMAND"' ERR

# Always runs: normal end, error exit, or exit after a signal
cleanup() {
    rm -f "${LOCK_FILE:-}"
}
trap cleanup EXIT

# Clean exit on Ctrl+C (SIGINT) or SIGTERM
graceful_shutdown() {
    printf '\n[INFO] Interrupt received. Shutting down cleanly...\n' >&2
    exit 130   # 128 + signal number 2 (SIGINT): callers can tell it was interrupted
}
trap graceful_shutdown SIGINT SIGTERM
```

`$?` is passed first so it is read before anything else can change it.

## Which trap does what

| Trap | Fires when | Use for |
| --- | --- | --- |
| `EXIT` | The shell exits for any reason | Removing temp files and locks (put cleanup here, not in `ERR`) |
| `ERR` | A command fails (same conditions as `set -e`) | Logging where the script failed |
| `INT` / `TERM` | Ctrl+C / `kill` | Stopping child processes, then `exit 130` / `exit 143` |
| `HUP` | Terminal closed | Re-reading configuration in long-running scripts |

`SIGKILL` (`kill -9`) cannot be trapped; nothing runs. Design scripts so a killed run can be restarted safely.

## Patterns

**Return codes on purpose.** Use `|| true` only when failure is genuinely fine, and say why:

```bash
grep -q "pattern" file.log || true   # absence of the pattern is not an error here
```

**Handle the failure yourself** when you need a fallback:

```bash
if ! output=$(curl -fsS --max-time 10 https://example.com/health); then
    echo "[WARN] health endpoint unreachable, using cached status" >&2
    output=$(cat /var/cache/app/health.json)
fi
```

**Retry with back-off** for network calls:

```bash
retry() {
    local attempts=$1; shift
    local delay=2
    local n
    for ((n = 1; n <= attempts; n++)); do
        "$@" && return 0
        echo "[WARN] attempt $n/$attempts failed: $*" >&2
        sleep "$delay"; delay=$((delay * 2))
    done
    return 1
}
retry 5 curl -fsS -o /tmp/feed.json https://example.com/feed.json
```

**One instance at a time** with `flock`:

```bash
exec 9>/var/lock/myjob.lock
flock -n 9 || { echo "[INFO] already running" >&2; exit 0; }
```

## Pitfalls

- `set -e` is ignored inside a function called from an `if` test or before `&&` / `||`. Check important results explicitly.
- `local var=$(cmd)` hides the exit status of `cmd` (it returns the status of `local`). Declare first: `local var; var=$(cmd)`.
- Output from `cmd | while read ...` is processed in a subshell; variables set in the loop are lost after it.

## Related

- [Defensive Bash scripting](defensive-scripting.md)
- [Bash overview](index.md)

## Sources

- [GNU Bash manual — Bourne Shell Builtins (trap)](https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html)
- [GNU Bash manual — The Set Builtin](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)
- [BashFAQ 105 — Why doesn't set -e do what I expected?](https://mywiki.wooledge.org/BashFAQ/105)
