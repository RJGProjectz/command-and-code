#!/usr/bin/env bash
# linux-triage.sh - collect volatile and persistence data from a Linux host.
#
# Usage: sudo ./linux-triage.sh [-o OUTPUT_DIR]
#   -o   parent directory for the collection (default: /var/tmp)
#
# Read-only apart from the output directory. Collects, in order of volatility:
# network -> processes -> sessions -> persistence -> accounts -> logs, then writes a
# SHA256 manifest. Missing tools are skipped, not fatal.
# Part of Command & Code.
# Snippets passed to runsh are single-quoted on purpose: they are evaluated by bash -c.
# shellcheck disable=SC2016
set -uo pipefail

OUT_PARENT="/var/tmp"
while getopts ':o:h' opt; do
  case "$opt" in
    o) OUT_PARENT="$OPTARG" ;;
    h|*) sed -n '2,10p' "$0"; exit 0 ;;
  esac
done

[[ $EUID -eq 0 ]] || echo "warning: not root - collection will be incomplete" >&2

HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_PARENT/triage-$HOST-$STAMP"
mkdir -p "$OUT"
umask 077

# run NAME COMMAND... - run a command, save stdout+stderr to NAME.txt, never abort the script
run() {
  local name="$1"; shift
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ ] $name (missing: $1)"
    return 0
  fi
  "$@" > "$OUT/$name.txt" 2>&1
  echo "[+] $name"
}

# runsh NAME 'shell snippet' - for pipelines and globs
runsh() {
  local name="$1" snippet="$2"
  bash -c "$snippet" > "$OUT/$name.txt" 2>&1
  echo "[+] $name"
}

# 1. Context
runsh context 'echo "collected_utc: $(date -u +%FT%TZ)"; echo "host: $(hostname -f 2>/dev/null || hostname)"; uname -a; cat /etc/os-release; uptime; timedatectl 2>/dev/null'

# 2. Network
run ss-listening ss -lntup
run ss-established ss -tnp state established
run ip-addr ip address
run ip-route ip route
run ip-neigh ip neigh
runsh resolver 'cat /etc/resolv.conf; echo; cat /etc/hosts; echo; resolvectl status 2>/dev/null'
runsh firewall 'nft list ruleset 2>/dev/null || iptables -S 2>/dev/null'

# 3. Processes
run ps-full ps -eo pid,ppid,user,lstart,etime,args --sort=start_time
runsh ps-forest 'ps -ef --forest'
runsh proc-exe 'ls -l /proc/[0-9]*/exe 2>/dev/null'
runsh proc-suspicious-exe "ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '\\(deleted\\)|/tmp/|/dev/shm/|/var/tmp/'"
run lsof-network lsof -i -P -n

# 4. Sessions and logins
run who who -a
run w w
runsh last 'last -n 200 -a -F 2>/dev/null'
runsh lastb 'lastb -n 200 -a -F 2>/dev/null'

# 5. Persistence
runsh crontabs 'cat /etc/crontab; ls -la /etc/cron.*; for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null) && printf "### %s\n%s\n" "$u" "$c"; done'
run systemd-timers systemctl list-timers --all --no-pager
run systemd-enabled systemctl list-unit-files --type=service --state=enabled --no-pager
runsh systemd-recent 'find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd -type f -mtime -30 -ls 2>/dev/null'
runsh authorized-keys 'for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
runsh sshd-effective 'sshd -T 2>/dev/null'
runsh preload 'ls -la /etc/ld.so.preload 2>/dev/null && cat /etc/ld.so.preload; grep -rs LD_PRELOAD /etc/environment /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null'
runsh shell-profiles 'ls -la /etc/profile.d; for f in /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile; do [ -f "$f" ] && echo "### $f" && grep -vE "^\s*(#|$)" "$f"; done'
run lsmod lsmod

# 6. Accounts and privileges
runsh passwd 'cat /etc/passwd'
runsh uid0 "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
runsh sudoers 'cat /etc/sudoers 2>/dev/null; for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
runsh suid 'find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null'

# 7. Files
runsh tmp-files 'ls -laR /tmp /var/tmp /dev/shm 2>/dev/null'
runsh recent-files-24h 'find / -xdev -type f -mtime -1 2>/dev/null | grep -vE "^/(proc|sys|run)/" | head -5000'
runsh shell-history 'for f in /root/.bash_history /home/*/.bash_history; do [ -f "$f" ] && { echo "### $f"; tail -n 200 "$f"; }; done'

# 8. Logs (copies)
mkdir -p "$OUT/logs"
for f in /var/log/auth.log* /var/log/secure* /var/log/syslog /var/log/messages /var/log/audit/audit.log; do
  [[ -f $f ]] && cp -p "$f" "$OUT/logs/" 2>/dev/null
done
runsh journal-48h 'journalctl --since "-48h" --no-pager 2>/dev/null | tail -n 200000'
echo "[+] logs"

# 9. Manifest
MANIFEST_TMP="$(mktemp)"
( cd "$OUT" && find . -type f -exec sha256sum {} + ) > "$MANIFEST_TMP"
mv "$MANIFEST_TMP" "$OUT/manifest-sha256.txt"
echo "Collection written to $OUT"
