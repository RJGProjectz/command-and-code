#!/usr/bin/env bash
# get-listening-ports.sh - list listening TCP/UDP sockets with process, binary path and user.
#
# Usage: sudo ./get-listening-ports.sh [-c]
#   -c   CSV output (default: aligned table)
#
# Read-only. Uses ss (iproute2) and /proc. Flags listeners whose binary is deleted
# or lives in /tmp, /var/tmp or /dev/shm.
# Part of Command & Code.
set -euo pipefail

CSV=0
while getopts ':ch' opt; do
  case "$opt" in
    c) CSV=1 ;;
    h|*) sed -n '2,8p' "$0"; exit 0 ;;
  esac
done

command -v ss >/dev/null 2>&1 || { echo "ss not found (install iproute2)" >&2; exit 1; }
[[ $EUID -eq 0 ]] || echo "warning: not root - process details for other users will be missing" >&2

print_row() {
  if [[ $CSV -eq 1 ]]; then
    printf '%s,%s,%s,%s,%s,%s,%s\n' "$@"
  else
    printf '%-5s %-28s %-8s %-18s %-10s %-45s %s\n' "$@"
  fi
}

print_row PROTO LOCAL PID PROCESS USER EXE FLAGS

# ss -H: no header. Columns: Netid State Recv-Q Send-Q Local Peer Process
ss -H -lntup 2>/dev/null | while read -r proto _state _recvq _sendq local _peer procinfo; do
  pid=""
  name=""
  if [[ ${procinfo:-} =~ \"([^\"]+)\",pid=([0-9]+) ]]; then
    name="${BASH_REMATCH[1]}"
    pid="${BASH_REMATCH[2]}"
  fi

  exe="" user="" flags=""
  if [[ -n $pid && -d /proc/$pid ]]; then
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
    case "$exe" in
      *"(deleted)"*) flags="DELETED_BINARY" ;;
      /tmp/*|/var/tmp/*|/dev/shm/*) flags="TEMP_PATH" ;;
    esac
  fi

  print_row "$proto" "$local" "${pid:--}" "${name:--}" "${user:--}" "${exe:--}" "$flags"
done
