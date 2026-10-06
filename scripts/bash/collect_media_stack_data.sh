#!/bin/bash
# collect_media_stack_data.sh
# description: Collects diagnostic data for the V2 Distributed Offload Architecture (Mothership / Brain / Worker)
# usage: sudo ./collect_media_stack_data.sh

OUT_FILE="media_stack_prework_data.txt"

# Clear output file if it exists
> "$OUT_FILE"

echo "==========================================================" | tee -a "$OUT_FILE"
echo " Forgepoint Media Stack - Pre-Work Data Collection        " | tee -a "$OUT_FILE"
echo " Date: $(date)                                            " | tee -a "$OUT_FILE"
echo " Hostname: $(hostname)                                    " | tee -a "$OUT_FILE"
echo " User: $(whoami)                                          " | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"

echo "" | tee -a "$OUT_FILE"
echo "[1] NETWORK & IP ADDRESSES" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
ip addr show >> "$OUT_FILE" 2>&1

echo "" | tee -a "$OUT_FILE"
echo "[2] UID/GID VALIDATION (Targeting UID/GID 1000)" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if id 1000 >/dev/null 2>&1; then
    id 1000 >> "$OUT_FILE" 2>&1
else
    echo "WARNING: User with UID 1000 does not exist on this node!" >> "$OUT_FILE"
fi

if getent group 1000 >/dev/null 2>&1; then
    getent group 1000 >> "$OUT_FILE" 2>&1
else
    echo "WARNING: Group with GID 1000 does not exist on this node!" >> "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "[3] MOUNT POINTS & NFS (fstab)" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
echo "--- /etc/fstab contents (filtering for NFS mounts) ---" >> "$OUT_FILE"
grep -i nfs /etc/fstab >> "$OUT_FILE" 2>&1 || echo "No NFS entries found in /etc/fstab." >> "$OUT_FILE"

echo "" >> "$OUT_FILE"
echo "--- Active NFS Mounts (mount command) ---" >> "$OUT_FILE"
mount | grep -i nfs >> "$OUT_FILE" 2>&1 || echo "No active NFS mounts found." >> "$OUT_FILE"

echo "" >> "$OUT_FILE"
echo "--- Disk Space (df -h) ---" >> "$OUT_FILE"
df -h >> "$OUT_FILE" 2>&1

echo "" | tee -a "$OUT_FILE"
echo "[4] DIRECTORY STRUCTURE & PERMISSIONS" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
# Combined list based on SOP and Guide
directories=(
    "/mnt/media"
    "/mnt/media_pool/media"
    "/mnt/ssd/downloads"
    "/mnt/ssd/downloads/incomplete"
    "/mnt/ssd/downloads/complete"
    "/mnt/ssd/tdarr-cache"
    "/opt/docker/sabnzbd"
    "/opt/docker/checkerr"
    "/data/movies"
    "/downloads"
)

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        echo "FOUND: $dir" >> "$OUT_FILE"
        ls -ld "$dir" >> "$OUT_FILE" 2>&1
    else
        echo "MISSING/UNMOUNTED: $dir" >> "$OUT_FILE"
    fi
    echo "---" >> "$OUT_FILE"
done

echo "" | tee -a "$OUT_FILE"
echo "[5] DOCKER PROCESSES & VOLUMES" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
if command -v docker &> /dev/null; then
    echo "--- Running Containers ---" >> "$OUT_FILE"
    docker ps -a >> "$OUT_FILE" 2>&1
else
    echo "Docker is not installed or not in PATH on this node." >> "$OUT_FILE"
fi

if command -v docker-compose &> /dev/null; then
    echo "--- Compose Version ---" >> "$OUT_FILE"
    docker-compose version >> "$OUT_FILE" 2>&1
elif docker compose version &> /dev/null; then
    echo "--- Compose Version (Docker Plugin) ---" >> "$OUT_FILE"
    docker compose version >> "$OUT_FILE" 2>&1
fi

echo "" | tee -a "$OUT_FILE"
echo "[6] NETWORK CONNECTIVITY TESTS" | tee -a "$OUT_FILE"
echo "----------------------------------------------------------" | tee -a "$OUT_FILE"
target_ips=("192.168.1.233" "192.168.1.240" "192.168.1.241")

for ip in "${target_ips[@]}"; do
    if ping -c 2 -W 2 "$ip" > /dev/null 2>&1; then
        echo "SUCCESS: Ping to $ip (Connectivity OK)" >> "$OUT_FILE"
    else
        echo "FAIL: Ping to $ip (Unreachable)" >> "$OUT_FILE"
    fi
done

echo "" | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"
echo " Data collection complete! Output saved to:               " | tee -a "$OUT_FILE"
echo " ./$OUT_FILE                                              " | tee -a "$OUT_FILE"
echo " Copy the contents of this file to your analysis prompt.  " | tee -a "$OUT_FILE"
echo "==========================================================" | tee -a "$OUT_FILE"
