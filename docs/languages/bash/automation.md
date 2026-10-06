---
title: Bash Scripting and Automation
platforms: [Linux]
languages: [Bash]
tasks: [Automation, Administration, Incident Response]
category: Automation
tags: [bash script template, set -euo pipefail, trap, getopts, ssh loop, cron]
aliases: [bash template, strict mode bash, run command on many hosts, ssh loop stdin, bash arguments]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Bash Scripting and Automation

## Script template

```bash
#!/usr/bin/env bash
# collect-example.sh — one-line description.
# Usage: collect-example.sh [-o OUTPUT_DIR] [-v]
set -euo pipefail
IFS=$'\n\t'

OUTPUT_DIR="./output"
VERBOSE=0

log() { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "${1}" "${2}" >&2; }
die() { log ERROR "$1"; exit 1; }

usage() { sed -n '2,3p' "$0"; exit 2; }

while getopts ':o:vh' opt; do
  case "$opt" in
    o) OUTPUT_DIR="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
command -v ss >/dev/null || die "ss not found"

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

mkdir -p "$OUTPUT_DIR"
[[ $VERBOSE -eq 1 ]] && log INFO "writing to $OUTPUT_DIR"
ss -lntup > "$OUTPUT_DIR/listening.txt"
log INFO "done"
```

| Line | Why |
| --- | --- |
| `set -e` | exit on any failing command |
| `set -u` | error on unset variables (catches typos) |
| `set -o pipefail` | a pipeline fails if any part fails, not just the last |
| `IFS=$'\n\t'` | word-splitting on newlines/tabs only — safer with filenames containing spaces |
| `trap cleanup EXIT` | cleanup runs however the script exits |

!!! note "`set -e` exceptions"
    Commands in `if` conditions, `||`/`&&` chains and `while` tests do not trigger `set -e`. `grep` returns 1 when nothing matches — use `grep ... || true` when "no match" is acceptable.

## Quote your variables

```bash
rm -rf "$DIR"/cache        # quoted: safe
rm -rf $DIR/cache          # unquoted: if DIR is empty this becomes rm -rf /cache
```

Use `"$@"` to pass all arguments through unchanged.

## Run a command on many hosts over SSH

```bash
while read -r host; do
  printf '== %s\n' "$host"
  ssh -n -o BatchMode=yes -o ConnectTimeout=5 "$host" 'uptime; ss -lnt | wc -l'
done < hosts.txt
```

!!! warning "`ssh -n` inside a read loop"
    Without `-n`, `ssh` reads from stdin and consumes the rest of `hosts.txt`, so only the first host runs.

## Arrays

```bash
paths=(/tmp /var/tmp /dev/shm)
for p in "${paths[@]}"; do find "$p" -type f -newer /etc/hostname; done
echo "count: ${#paths[@]}"
```

## Timeouts

```bash
timeout 10 curl -s https://example.com/health || echo "health check failed or timed out"
```

## Cron-safe scripts

Cron runs with a minimal environment. Set `PATH` explicitly, use absolute paths, and redirect output:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
15 6 * * * /opt/cc/scripts/linux-triage.sh -o /var/tmp/triage >> /var/log/cc-triage.log 2>&1
```

## Lint before you ship

```bash
shellcheck script.sh
bash -n script.sh        # syntax check only
```

## Related

- [Bash text processing](text-processing.md)
- [Bash toolbox scripts](../../toolbox/bash.md)
- [PowerShell automation](../powershell/automation.md)

## Sources

- [Bash Reference Manual — The Set Builtin](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)
- [ShellCheck](https://www.shellcheck.net/)
