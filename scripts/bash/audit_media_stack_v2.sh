#!/bin/bash
# audit_media_stack_v2.sh
# description: Automates a strict compliance scan against the V2.0 Distributed Architecture ruleset.
# usage: sudo ./audit_media_stack_v2.sh

OUT_FILE="v2_audit_results.txt"
> "$OUT_FILE"

echo "==========================================================" | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"
echo " Forgepoint Media Stack V2.1 Audit Scan                   " | tee -a "$OUT_FILE"
echo " Hostname: $(hostname) | Date: $(date)                    " | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"

echo "" | tee -a "$OUT_FILE"
echo "[1] IDENTITY UNIFICATION CHECK (mediasvc)" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if id mediasvc >/dev/null 2>&1; then
    echo "[PASS] mediasvc account exists." | tee -a "$OUT_FILE"
    id mediasvc >> "$OUT_FILE"
else
    echo "[FAIL] Critical Warning: mediasvc account is missing!" | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[2] V2.0 DIRECTORY INTEGRITY" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
declare -a dirs=(
    "/opt/docker"
    "/opt/docker/config"
)

# Detect if we are on the Ingest Worker, Compute Worker, or Brain based on hostname or IP
if ip addr | grep -q "192.168.1.240" || [ "$(hostname)" == "Lab" ]; then
    echo "-> Running Ingest Worker (.240) specific path checks:" | tee -a "$OUT_FILE"
    dirs+=("/mnt/ssd/downloads/incomplete" "/mnt/ssd/downloads/complete" "/mnt/ssd/transcode" "/opt/docker/config/sabnzbd")
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            owner=$(stat -c '%U:%G' "$dir")
            echo "[PASS] Found $dir (Owner: $owner)" | tee -a "$OUT_FILE"
        else
            echo "[FAIL] Missing V2 standard path: $dir" | tee -a "$OUT_FILE"
        fi
    done

elif ip addr | grep -q "192.168.1.241" || [ "$(hostname)" == "PMX2" ]; then
    echo "-> Running Brain (.241) specific path checks:" | tee -a "$OUT_FILE"
    dirs+=("/mnt/worker_ssd/downloads" "/mnt/nas/media" "/opt/docker/config/sonarr")
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            owner=$(stat -c '%U:%G' "$dir")
            echo "[PASS] Found $dir (Owner: $owner)" | tee -a "$OUT_FILE"
        else
            echo "[FAIL] Missing V2 standard path: $dir" | tee -a "$OUT_FILE"
        fi
    done

elif ip addr | grep -q "192.168.1.242" || [ "$(hostname)" == "PXM3" ]; then
    echo "-> Running Compute Worker (.242) specific path checks:" | tee -a "$OUT_FILE"
    dirs+=("/mnt/ssd/transcode" "/mnt/nas/media" "/opt/docker/config/tdarr-node")
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            owner=$(stat -c '%U:%G' "$dir")
            echo "[PASS] Found $dir (Owner: $owner)" | tee -a "$OUT_FILE"
        else
            echo "[FAIL] Missing V2 standard path: $dir" | tee -a "$OUT_FILE"
        fi
    done
else
    echo "Could not identify node IP/Hostname. Defaulting to basic checks." | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[3] EXPLICIT DOCKER COMPOSE FILES" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if [ -f "/opt/docker/compose-worker.yml" ] || [ -f "/opt/docker/compose-ingest.yml" ]; then
    echo "[PASS] Ingest-role compose file detected." | tee -a "$OUT_FILE"
fi
if [ -f "/opt/docker/compose-brain.yml" ]; then
    echo "[PASS] Brain-role compose file detected." | tee -a "$OUT_FILE"
fi
if [ -f "/opt/docker/compose-compute.yml" ]; then
    echo "[PASS] Compute-role compose file detected." | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[4] NFS BRIDGE INTEGRITY" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if [ "$(hostname)" == "Lab" ]; then
    if grep -q "/mnt/ssd/downloads" /etc/exports 2>/dev/null; then
        echo "[PASS] Worker is exporting NFS bridge." | tee -a "$OUT_FILE"
    else
        echo "[FAIL] Worker is NOT exporting /mnt/ssd/downloads via /etc/exports!" | tee -a "$OUT_FILE"
    fi
elif [ "$(hostname)" == "PMX2" ]; then
    if mount | grep -q "worker_ssd"; then
        echo "[PASS] Brain successfully mounted remote /mnt/worker_ssd/downloads." | tee -a "$OUT_FILE"
    else
        echo "[FAIL] Brain has NOT successfully mounted the Worker's active NFS bridge!" | tee -a "$OUT_FILE"
    fi
fi

echo "" | tee -a "$OUT_FILE"
echo "[5] CONTAINER ROLE AUDIT" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
echo "Currently Running V2 Containers:" | tee -a "$OUT_FILE"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | tee -a "$OUT_FILE"

echo "==========================================================" | tee -a "$OUT_FILE"
echo " V2.0 Audit Complete. Log saved to: $OUT_FILE             " | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"
