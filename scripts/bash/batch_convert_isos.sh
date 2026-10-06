#!/bin/bash
# batch_convert_isos.sh
# description: Converts legacy ISO files to MKV natively using HandBrake CLI within a Docker container.
# usage: ./batch_convert_isos.sh (Run on PXM3 Compute Node)

echo "=========================================================="
echo " Starting Automated ISO-to-MKV Batch Conversion"
echo " Node: $(hostname)"
echo " Dependency check: Docker Alpine w/ HandBrakeCLI"
echo "=========================================================="

if ! command -v docker &> /dev/null; then
    echo "[!] FATAL: Docker is not installed on this node. This script must run on the Compute Node."
    exit 1
fi

if ! mountpoint -q /mnt/nas/media && ! mountpoint -q /mnt/media; then
    echo "[!] FATAL: NAS Mount not detected. Exiting to prevent errors."
    exit 1
fi

echo "[*] Spinning up conversion environment. This will take some time..."
# We use Alpine Linux to install HandBrakeCLI dynamically, then loop through the ISOs.
# The container maps the entire TrueNAS media directory for read/write access.

docker run --rm -v /mnt/nas/media:/mnt/nas/media alpine sh -c "
echo '[*] Installing HandBrakeCLI inside container...'
apk add --no-cache handbrake > /dev/null 2>&1

echo '[*] Scanning for .iso files in /mnt/nas/media/movies/ ...'
find /mnt/nas/media/movies/ -type f -name '*.iso' | while read -r iso_file; do
    # Strip the .iso extension and append .mkv to retain the exact filename for the ARRs
    mkv_file=\"\${iso_file%.iso}.mkv\"
    
    echo \"----------------------------------------------------------\"
    echo \"[PROCESS] Converting: \$iso_file\"
    echo \"[TARGET]  Output  : \$mkv_file\"
    echo \"----------------------------------------------------------\"
    
    # Run the extraction. --preset is set to high quality, --main-feature pulls the longest title.
    # We redirect stdin from /dev/null because HandBrakeCLI consumes stdin, which breaks the while read loop.
    if HandBrakeCLI -i \"\$iso_file\" -o \"\$mkv_file\" --preset \"Super HQ 1080p30 Surround\" --main-feature < /dev/null; then
        echo \"[SUCCESS] Conversion completed. Deleting original ISO...\"
        rm -f \"\$iso_file\"
    else
        echo \"[ERROR] HandBrake encountered an error processing \$iso_file. ISO retained.\"
    fi
done
"

echo "=========================================================="
echo " Batch Conversion Finished."
echo " Action Required: Go to Radarr and run 'Update Library' to adopt the new MKVs."
echo "=========================================================="
