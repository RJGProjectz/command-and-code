---
title: Defensive Bash Scripting & Enterprise Boilerplate
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Automation
  - Hardening
verified: true
last_verified: 2026-10-12
difficulty: basic
tags:
  - bash
  - scripting
  - defensive
  - boilerplate
---

# Defensive Bash Scripting & Enterprise Boilerplate

Production standard template for writing reliable, self-documenting, and error-resilient Bash scripts.

## The Production Boilerplate

```bash
#!/usr/bin/env bash
# ==============================================================================
# Script Name   : backup-database.sh
# Description   : Automated database dump with compression and retention pruning
# Author        : Platform Engineering
# Usage         : backup-database.sh [--dry-run] <target-dir>
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME=$(basename "$0")
DRY_RUN=0

log()  { printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >&2; }
die()  { log ERROR "$1"; exit "${2:-1}"; }
usage() { printf 'Usage: %s [--dry-run] <target-dir>\n' "$SCRIPT_NAME" >&2; exit 2; }

# Arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -*) die "unknown option: $1" 2 ;;
        *)  break ;;
    esac
done
[ $# -eq 1 ] || usage
TARGET_DIR=$1
[ -d "$TARGET_DIR" ] || die "not a directory: $TARGET_DIR"

# Required tools
for cmd in gzip find; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing dependency: $cmd"
done

# Trap cleanup on exit or error
TMP_DIR=$(mktemp -d -t "app_run.XXXXXX")
cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# Run a state-changing command, or only print it in dry-run mode
run() {
    if [ "$DRY_RUN" -eq 1 ]; then log DRYRUN "$*"; else "$@"; fi
}

# Script logic starts here
log INFO "Running in temporary scratch directory: ${TMP_DIR}"
run find "$TARGET_DIR" -name '*.sql.gz' -mtime +14 -delete
```

### Explaining the Strict Flags

- `set -e`: Exit immediately if any command returns a non-zero exit status (not inside `if`, `while`, `&&` / `||` tests).
- `set -u`: Treat unset variables as an error and exit immediately.
- `set -o pipefail`: A pipeline fails if any command in it fails, not only the last one.
- `IFS=$'\n\t'`: Splits words only on newlines and tabs, preventing spaces in filenames from breaking `for` loops.

## Rules that prevent most bugs

| Rule | Wrong | Right |
| --- | --- | --- |
| Quote every expansion | `rm -rf $DIR/` | `rm -rf "${DIR:?}/"` (`:?` aborts if empty) |
| Loop over files with globs, not `ls` | `for f in $(ls *.log)` | `for f in ./*.log; do [ -e "$f" ] || continue; ...` |
| Read lines safely | `for line in $(cat file)` | `while IFS= read -r line; do ...; done < file` |
| Temp files | `/tmp/myscript.tmp` (predictable, raceable) | `mktemp` + `trap ... EXIT` |
| Test commands directly | `cmd; if [ $? -eq 0 ]` | `if cmd; then` |
| Arguments that may start with `-` | `rm $file` | `rm -- "$file"` |

## Security notes

- Never `eval` input, and never build commands by concatenating strings; pass arguments as an array: `args=(--user "$user"); tool "${args[@]}"`.
- Secrets: read them from a file or environment variable set by the caller, not from command-line arguments (visible in `ps`). Do not `set -x` in scripts that handle secrets.
- Scripts run by root (cron, systemd) must be owned by root and not writable by anyone else; otherwise any user who can edit the script becomes root.
- Use absolute paths or set `PATH` explicitly at the top of scripts run by cron or sudo.

## Check scripts before running them

```bash
bash -n script.sh        # syntax only
shellcheck script.sh     # common bugs: quoting, unused variables, bad tests
```

## Related

- [Bash error handling and traps](error-handling-traps.md)
- [Bash overview](index.md)

## Sources

- [GNU Bash manual — The Set Builtin](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)
- [ShellCheck wiki](https://www.shellcheck.net/wiki/)
- [BashFAQ / BashPitfalls (Greg's Wiki)](https://mywiki.wooledge.org/BashPitfalls)
