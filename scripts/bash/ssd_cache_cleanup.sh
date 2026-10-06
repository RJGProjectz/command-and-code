#!/bin/bash
# ssd_cache_cleanup.sh
# description: V2.2 Mount-Aware maintenance script to prevent SSD overflow.
# usage: ./ssd_cache_cleanup.sh (Designed to run via crontab)

LOG_FILE="/var/log/ssd_cleanup.log"
exec >> $LOG_FILE 2>&1

echo "--- Run Date: $(date) ---"

# 1. MOUNT SAFETY CHECK
# Abort if the NAS is unmounted to prevent deleting files that haven't been moved yet.
# Standard path is /mnt/nas/media, but environment uses /mnt/media.
if ! mountpoint -q /mnt/media; then
    echo "[!] NAS MOUNT MISSING. Attempting auto-repair..."
    mount -a
    sleep 2
    if ! mountpoint -q /mnt/media; then
        echo "[FATAL] NAS Mount failed. Aborting cleanup."
        exit 1
    fi
fi

# 2. PRUNE STALE INCOMPLETE (5 Day Grace)
# Clears stalled or broken downloads that are hogging space.
echo "[*] Pruning incomplete downloads older than 5 days..."
find /mnt/ssd/downloads/incomplete -mindepth 1 -mtime +5 -exec rm -rvf {} +

# 3. PRUNE ORPHANED COMPLETE (3 Day Grace)
# Clears leftover debris (.nfo, .txt, empty folders) after Sonarr/Radarr moves.
# Excludes active un-parses (_UNPACK_) and user-flagged failures (_FAILED_).
echo "[*] Pruning completed debris older than 3 days (excluding active unpacks)..."
find /mnt/ssd/downloads/complete -mindepth 1 -mtime +3 \
    ! -name "_UNPACK_*" \
    ! -name "_FAILED_*" \
    -exec rm -rvf {} +

# 4. EMERGENCY USAGE ALERT
USAGE=$(df -h /mnt/ssd | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USAGE" -gt 90 ]; then
    echo "[CRITICAL] SSD usage is at ${USAGE}%! Check for stalled moves."
fi
