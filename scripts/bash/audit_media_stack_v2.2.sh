#!/bin/bash
# audit_media_stack_v2.2.sh
# description: Automates a strict compliance scan against the V2.2 Quad-Node Architecture.
# Includes checks for Discovery Layer (Seerr/FlareSolverr), Storage Safeguards, and Mount Persistence.
# usage: sudo ./audit_media_stack_v2.2.sh

OUT_FILE="v2.2_audit_results.txt"
> "$OUT_FILE"

echo "==========================================================" | tee -a "$OUT_FILE"
echo " Forgepoint Media Stack V2.2 Audit Scan                   " | tee -a "$OUT_FILE"
echo " Hostname: $(hostname) | Date: $(date)                    " | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"

echo "" | tee -a "$OUT_FILE"
echo "[1] IDENTITY UNIFICATION CHECK (mediasvc)" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if id mediasvc >/dev/null 2>&1; then
    echo "[PASS] mediasvc account exists (UID: 1000)." | tee -a "$OUT_FILE"
else
    echo "[FAIL] Critical Warning: mediasvc account is missing!" | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[2] V2.2 DIRECTORY INTEGRITY" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
declare -a dirs=(
    "/opt/docker"
    "/opt/docker/config"
)

# Node-specific checks
if ip addr | grep -q "192.168.1.240" || [ "$(hostname)" == "Lab" ]; then
    echo "-> Running Ingest Worker (.240) specific checks:" | tee -a "$OUT_FILE"
    dirs+=("/mnt/ssd/downloads/incomplete" "/mnt/ssd/downloads/complete" "/opt/docker/config/sabnzbd")
elif ip addr | grep -q "192.168.1.241" || [ "$(hostname)" == "PMX2" ]; then
    echo "-> Running Brain (.241) specific checks:" | tee -a "$OUT_FILE"
    dirs+=("/mnt/nas/media" "/mnt/media" "/opt/docker/config/sonarr" "/opt/docker/config/seerr" "/opt/docker/config/flaresolverr")
elif ip addr | grep -q "192.168.1.242" || [ "$(hostname)" == "PXM3" ]; then
    echo "-> Running Compute Worker (.242) specific checks:" | tee -a "$OUT_FILE"
    dirs+=("/mnt/ssd/transcode" "/mnt/nas/media" "/mnt/media" "/opt/docker/config/tdarr-node")
fi

for dir in "${dirs[@]}"; do
    if [ -d "$dir" ]; then
        owner=$(stat -c '%u:%g' "$dir")
        if [ "$owner" == "1000:1000" ]; then
            echo "[PASS] $dir (Owner: mediasvc)" | tee -a "$OUT_FILE"
        else
            echo "[WARN] $dir exists but has wrong owner: $owner (Expected 1000:1000)" | tee -a "$OUT_FILE"
        fi
    else
        echo "[FAIL] Missing V2.2 path: $dir" | tee -a "$OUT_FILE"
    fi
done

echo "" | tee -a "$OUT_FILE"
echo "[3] NETWORK & MOUNT PERSISTENCE" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if mount | grep -q "192.168.1.233"; then
    echo "[PASS] Node successfully mounted TrueNAS Mothership Media." | tee -a "$OUT_FILE"
else
    echo "[FAIL] Node is NOT mounted to TrueNAS Mothership!" | tee -a "$OUT_FILE"
fi

if grep -qE "/mnt/(nas/)?media" /etc/fstab; then
    echo "[PASS] FSTAB contains persistent NAS mount entry." | tee -a "$OUT_FILE"
else
    echo "[FAIL] FSTAB is missing the NAS mount entry!" | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[4] STORAGE PRESSURE CHECK" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
USAGE=$(df -h | grep "/mnt/ssd" | awk '{print $5}' | sed 's/%//')
if [ -z "$USAGE" ]; then
    echo "[INFO] No local SSD mount detected on this node." | tee -a "$OUT_FILE"
elif [ "$USAGE" -gt 90 ]; then
    echo "[FAIL] SSD usage is at ${USAGE}%! Stalls imminent." | tee -a "$OUT_FILE"
else
    echo "[PASS] SSD usage is healthy at ${USAGE}%." | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[5] CONTAINER STATUS AUDIT" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | tee -a "$OUT_FILE"

echo "==========================================================" | tee -a "$OUT_FILE"
echo " V2.2 Audit Complete. Results: $OUT_FILE" | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"
