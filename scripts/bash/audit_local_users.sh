#!/usr/bin/env bash
# Audits local user accounts, human accounts (UID >= 1000), and sudoers membership.
set -euo pipefail

echo "=== Human Accounts (UID >= 1000) ==="
awk -F: '($3 >= 1000 && $1 != "nobody") {printf "User: %-16s UID: %-6s Shell: %s\n", $1, $3, $7}' /etc/passwd

echo ""
echo "=== Sudoers / Wheel Group Members ==="
if getent group sudo >/dev/null 2>&1; then
    echo "sudo group: $(getent group sudo | cut -d: -f4)"
fi
if getent group wheel >/dev/null 2>&1; then
    echo "wheel group: $(getent group wheel | cut -d: -f4)"
fi
