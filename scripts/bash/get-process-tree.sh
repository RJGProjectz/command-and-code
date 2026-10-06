#!/usr/bin/env bash
# get-process-tree.sh - show the ancestors and descendants of a PID with command lines.
#
# Usage: ./get-process-tree.sh PID
#
# Read-only. Uses /proc and ps only (no pstree dependency).
# Part of Command & Code.
set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[0-9]+$ ]]; then
  sed -n '2,6p' "$0"
  exit 2
fi

TARGET="$1"
[[ -d /proc/$TARGET ]] || { echo "PID $TARGET is not running" >&2; exit 1; }

describe() {
  local pid="$1"
  local user cmd exe
  user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
  cmd="$( { tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null || true)"
  [[ -n $cmd ]] || cmd="[$(cat "/proc/$pid/comm" 2>/dev/null || echo '?')]"
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null || echo '-')"
  printf '%s (user=%s exe=%s) %s' "$pid" "${user:--}" "$exe" "$cmd"
}

ppid_of() {
  awk '/^PPid:/ {print $2}' "/proc/$1/status" 2>/dev/null
}

# Ancestors, oldest first
chain=()
pid="$TARGET"
while :; do
  parent="$(ppid_of "$pid")"
  [[ -n $parent && $parent -ne 0 ]] || break
  chain=("$parent" "${chain[@]}")
  pid="$parent"
done

depth=0
for p in "${chain[@]}"; do
  printf '%*s%s\n' $((depth * 2)) '' "$(describe "$p")"
  depth=$((depth + 1))
done
printf '%*s>> %s\n' $((depth * 2)) '' "$(describe "$TARGET")"

# Descendants
print_children() {
  local parent="$1" level="$2" child
  for child in $(ps -o pid= --ppid "$parent" 2>/dev/null); do
    [[ -d /proc/$child ]] || continue
    printf '%*s%s\n' $((level * 2)) '' "$(describe "$child")"
    print_children "$child" $((level + 1))
  done
}
print_children "$TARGET" $((depth + 1))
