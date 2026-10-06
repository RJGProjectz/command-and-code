#!/bin/bash
# setup_compute_node_v2.sh
# description: Bootstraps the new V2.1 PXM3 Compute Node (.242) from scratch.
# usage: ssh into PXM3 (192.168.1.242) and run: chmod +x setup_compute_node_v2.sh && ./setup_compute_node_v2.sh

echo "========================================="
echo " Provisioning PXM3 Compute Node (.242)   "
echo "========================================="

echo "[*] Creating 'mediasvc' unified identity (UID/GID 1000)..."
groupadd -g 1000 mediasvc 2>/dev/null
useradd -u 1000 -g 1000 -d /home/<user> -s /bin/bash mediasvc 2>/dev/null

echo "[*] Building strictly mapped V2 directories..."
mkdir -p /opt/docker/config/tdarr-node
mkdir -p /opt/docker/config/checkrr
touch /opt/docker/config/checkrr/checkrr.db
wget -q https://raw.githubusercontent.com/aetaric/checkrr/main/checkrr.yaml.example -O /opt/docker/config/checkrr/checkrr.yaml || touch /opt/docker/config/checkrr/checkrr.yaml
mkdir -p /mnt/ssd/transcode
mkdir -p /mnt/nas/media

echo "[*] Hooking into TrueNAS Mothership (.233)..."
if ! grep -q "/mnt/nas/media" /etc/fstab; then
    echo "192.168.1.233:/mnt/Mothership/Media /mnt/nas/media nfs defaults,soft,intr 0 0" >> /etc/fstab
fi
mount -a 2>/dev/null

echo "[*] Generating compose-compute.yml..."
cat << 'EOF' > /opt/docker/compose-compute.yml
version: "3"
services:
  tdarr-node:
    container_name: tdarr-node
    image: haveagitgat/tdarr_node:latest
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Etc/UTC
      - serverIP=192.168.1.241
      - serverPort=8266
      - nodeID=Compute-Worker-01
    volumes:
      - /opt/docker/config/tdarr-node:/config
      - /mnt/nas/media:/media
      - /mnt/ssd/transcode:/temp
    restart: unless-stopped

  checkrr:
    container_name: checkrr
    image: aetaric/checkrr:latest
    volumes:
      - /opt/docker/config/checkrr/checkrr.yaml:/etc/checkrr.yaml
      - /opt/docker/config/checkrr/checkrr.db:/checkrr.db
      - /mnt/nas/media:/media
    ports:
      - 8585:8585
    restart: unless-stopped
EOF

echo "[*] Enforcing mediasvc permissions..."
chown -R mediasvc:mediasvc /mnt/ssd /opt/docker
chmod -R 777 /mnt/ssd/transcode

echo "========================================="
echo "[SUCCESS] PXM3 Provisioned!"
echo "Next Actions:"
echo "1. Verify network mount: ls -l /mnt/nas/media"
echo "2. Spin up the Compute Stack: cd /opt/docker && docker compose -f compose-compute.yml up -d"
