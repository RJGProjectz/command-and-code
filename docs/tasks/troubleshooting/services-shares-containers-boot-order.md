---
title: Auditing Services, Share Mounts and Containers — Boot Order and the Common Failures
type: workflow
platforms: [Linux, Proxmox]
languages: [Bash]
tasks: [Troubleshooting, Administration, Assurance]
category: Workflow
tags: [workflow, troubleshooting, systemd, docker, docker compose, nfs, smb, cifs, fstab, mount, automount, bind propagation, rslave, homelab, nas, boot order]
aliases: [container sees empty share after reboot, docker empty volume after power loss, nfs mount not visible in container, docker starts before nfs, RequiresMountsFor docker, rprivate rslave, jellyfin empty library after reboot, x-systemd.automount docker, stale file handle, nfs hard mount hang]
difficulty: intermediate
verified: true
last_verified: 2026-10-18
---

# Auditing Services, Share Mounts and Containers — Boot Order and the Common Failures

**Symptom:** after a reboot or power loss, containers come up "running" and even "healthy", but the network share inside them is empty. Restarting the container by hand fixes it — until the next power cut.

**Audience:** homelab and small-business admins running Linux hosts (Proxmox VE / Debian with systemd) that run Docker containers whose data lives on a NAS share (NFS or SMB/CIFS).

**The short answer:** Docker started before the share was mounted, and the container bound itself to the *empty local directory* under the mount point. With Docker's default bind propagation (`rprivate`) the share that is mounted a few seconds later never shows up inside the container. Fix it in layers: make the mount reliable (fstab), make Docker wait for it (systemd drop-in), make late mounts visible (`:rslave`), and **measure** that every container sees its share (watchdog + metric). A running container is not evidence that it works.

!!! info "Measured vs general guidance"
    Paragraphs marked **Measured (incident)** describe what was observed on the affected hosts. Everything else is general guidance, checked against the systemd, `nfs(5)` and Docker documentation (links at the end). Times are shown in America/Edmonton (MDT, UTC−06:00 until 2026-11-01, then MST, UTC−07:00).

## 1. Case study — the empty media library

**Measured (incident):**

- After every power loss the media stack (Jellyfin, Sonarr, Radarr, Tdarr, checkrr) came back `Up` and healthy, but showed an **empty library**. The only fix was restarting every container by hand.
- On host A, `docker.service` became active **3 seconds before** the NFS mount finished. The bind mount `/mnt/nas/media:/media` was bound to the empty directory `/mnt/nas/media` on the root filesystem.
- The bind propagation was `rprivate` (Docker's default), so the NFS mount that arrived 3 seconds later was not propagated into the container. One container stayed empty for **5 days**, until it was restarted.
- On host B the `/etc/fstab` line used `bg`, so nothing waited for the mount, and one share came from **another Proxmox node** (a boot dependency on a different host).
- A batch tool that runs `ffmpeg` inside a container would have failed on every file. It was changed to **refuse to start** when the container sees an empty share.
- Nothing alerted: `docker ps` said `Up`, the healthchecks passed, the host monitoring saw the NFS mount on the host. The only symptom was user-visible.

**Why it happens (general):** a bind mount pins whatever is at the source path *at the moment the container starts*. If the share is not mounted yet, that is the empty mount-point directory on the local disk. A mount that arrives later is a new mount *on the host*; whether it appears inside the container depends only on bind propagation. With `rprivate` it never does.

## 2. How boot order really works

systemd starts units in parallel and only orders them where a dependency says so. The relevant pieces:

| Unit | What it means | Where the ordering comes from |
| :--- | :--- | :--- |
| `network-online.target` | The network is configured "enough" (depends on the wait-online service of your network stack, e.g. `systemd-networkd-wait-online` or `ifupdown-wait-online` / `networking.service` on Debian) | Pulled in by network mounts and by services that ask for it |
| `mnt-nas-media.mount` | Mount unit generated from the `/etc/fstab` line by `systemd-fstab-generator`. Name = escaped path (`systemd-escape -p --suffix=mount /mnt/nas/media`) | Network mounts get `After=` + `Wants=network-online.target` and `Before=remote-fs.target` automatically |
| `remote-fs.target` | "All network mounts that are required are done" | Each network mount *without* `nofail` is ordered before it and required by it |
| `docker.service` | dockerd. On Debian it has `After=network-online.target` (and containerd), **not** `remote-fs.target` or your mount | The packaged unit file — nothing about your shares |
| Containers | Started **by dockerd** as soon as it is up, for every container with restart policy `always` or `unless-stopped` (not `no`, and `on-failure` only after a failure) | No systemd ordering at all — systemd does not know about containers |

So with the stock units, `docker.service` and the NFS mount both wait for `network-online.target`, and then **race**. Whoever wins decides whether your containers see the share.

### Boot sequence after the fix

<figure markdown>
<svg viewBox="0 0 760 640" role="img" aria-labelledby="bootTitle bootDesc" style="max-width:760px;width:100%;height:auto;font-family:var(--md-text-font-family,sans-serif)" xmlns="http://www.w3.org/2000/svg">
<title id="bootTitle">Boot order: network shares before Docker before containers</title>
<desc id="bootDesc">Host boots, local-fs.target, network-online.target, the NAS NFS mount, remote-fs.target, docker.service with RequiresMountsFor, then containers with rslave binds, then the watchdog metric. A share from another node arrives through an automount. A dashed red line shows the incident race where docker started before the mount.</desc>
<defs>
<marker id="aB" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#1e88e5"/></marker>
<marker id="aO" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#ef6c00"/></marker>
<marker id="aG" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#2e7d32"/></marker>
<marker id="aR" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#d32f2f"/></marker>
</defs>
<g fill="none" stroke="currentColor" stroke-width="1.5">
<rect x="200" y="20" width="260" height="44" rx="4"/>
<rect x="200" y="90" width="260" height="44" rx="4"/>
<rect x="200" y="160" width="260" height="44" rx="4"/>
<rect x="200" y="230" width="260" height="44" rx="4"/>
<rect x="200" y="300" width="260" height="44" rx="4"/>
<rect x="200" y="370" width="260" height="44" rx="4"/>
<rect x="200" y="440" width="260" height="44" rx="4"/>
<rect x="200" y="510" width="260" height="44" rx="4"/>
<rect x="20" y="230" width="150" height="44" rx="4" stroke="#ef6c00"/>
<rect x="520" y="160" width="220" height="44" rx="4" stroke="#2e7d32"/>
<rect x="520" y="300" width="220" height="44" rx="4" stroke="#2e7d32"/>
</g>
<g fill="currentColor" font-size="13" text-anchor="middle">
<text x="330" y="47">Host A powers on (systemd)</text>
<text x="330" y="117">local-fs.target</text>
<text x="330" y="187">network-online.target</text>
<text x="330" y="249">mnt-nas-media.mount</text>
<text x="330" y="266" font-size="11">fstab: nfs, _netdev, no bg</text>
<text x="330" y="327">remote-fs.target</text>
<text x="330" y="389">docker.service</text>
<text x="330" y="406" font-size="11">RequiresMountsFor=/mnt/nas/media</text>
<text x="330" y="459">containers start (restart policy)</text>
<text x="330" y="476" font-size="11">/mnt/nas/media:/media:rslave</text>
<text x="330" y="529">watchdog timer + metric</text>
<text x="330" y="546" font-size="11">container_share_visible = 1 / 0</text>
<text x="95" y="249">NAS</text>
<text x="95" y="266" font-size="11">export ready</text>
<text x="630" y="179">Node B (other host)</text>
<text x="630" y="196" font-size="11">NFS export</text>
<text x="630" y="319">mnt-nodeb.automount</text>
<text x="630" y="336" font-size="11">x-systemd.automount</text>
</g>
<g fill="none" stroke-width="2">
<path d="M330,64 V90" stroke="#1e88e5" marker-end="url(#aB)"/>
<path d="M330,134 V160" stroke="#1e88e5" marker-end="url(#aB)"/>
<path d="M330,204 V230" stroke="#1e88e5" marker-end="url(#aB)"/>
<path d="M170,252 H200" stroke="#ef6c00" marker-end="url(#aO)"/>
<path d="M330,274 V300" stroke="#ef6c00" marker-end="url(#aO)"/>
<path d="M330,344 V370" stroke="#ef6c00" marker-end="url(#aO)"/>
<path d="M330,414 V440" stroke="#1e88e5" marker-end="url(#aB)"/>
<path d="M330,484 V510" stroke="#1e88e5" marker-end="url(#aB)"/>
<path d="M630,204 V300" stroke="#2e7d32" marker-end="url(#aG)"/>
<path d="M630,344 V462 H460" stroke="#2e7d32" marker-end="url(#aG)"/>
<path d="M460,182 H490 V392 H460" stroke="#d32f2f" stroke-dasharray="6 4" marker-end="url(#aR)"/>
</g>
<g fill="#d32f2f" font-size="11">
<text x="500" y="232">Before the fix: docker only</text>
<text x="500" y="247">waited for the network and</text>
<text x="500" y="262">started 3 s before the mount</text>
<text x="500" y="277">(measured, host A)</text>
</g>
<g font-size="12" fill="currentColor">
<path d="M20,590 H50" stroke="#1e88e5" stroke-width="2"/><text x="56" y="594">Host A (local systemd ordering)</text>
<path d="M280,590 H310" stroke="#ef6c00" stroke-width="2"/><text x="316" y="594">NAS share</text>
<path d="M420,590 H450" stroke="#2e7d32" stroke-width="2"/><text x="456" y="594">Node B share (cross-host)</text>
<path d="M20,618 H50" stroke="#d32f2f" stroke-width="2" stroke-dasharray="6 4"/><text x="56" y="622">Incident race (before the fix)</text>
</g>
</svg>
<figcaption>Line colour = the host the dependency comes from. Only straight lines with right-angle corners.</figcaption>
</figure>

## 3. The fix, in layers

No single layer is enough. Layer A makes the mount reliable, B makes Docker wait for it, C survives a mount that still arrives late (automount, NAS reboot, remount), D and E detect what A–C miss.

### Layer A — the `/etc/fstab` line

```text
# NFS from the NAS — Docker depends on it
nas.lan:/volume1/media  /mnt/nas/media  nfs4  _netdev,hard,timeo=150,retrans=3,x-systemd.mount-timeout=120  0  0

# SMB/CIFS equivalent (credentials file is root:root 0600)
//nas.lan/media  /mnt/nas/media  cifs  _netdev,credentials=/etc/samba/nas.cred,uid=1000,gid=1000,file_mode=0664,dir_mode=0775,x-systemd.mount-timeout=120  0  0

# Share from ANOTHER node — mount on first access instead of at boot
pve2.lan:/tank/backup  /mnt/nodeb/backup  nfs4  _netdev,x-systemd.automount,x-systemd.mount-timeout=60,x-systemd.idle-timeout=0  0  0
```

| Option | Use it? | Why |
| :--- | :--- | :--- |
| `_netdev` | Yes, on every network share | Tells systemd the mount needs the network, so it is ordered after `network-online.target` and before `remote-fs.target`. NFS/CIFS are detected automatically, but the explicit flag also covers file systems systemd cannot recognise (iSCSI, NBD, FUSE). |
| `bg` | **No** | `mount.nfs` with `bg` forks a background retry and returns success at once. Under systemd, the generator rewrites it: it prepends `x-systemd.mount-timeout=infinity,retry=10000` and appends `fg,nofail`. `nofail` means the mount is **not ordered before `remote-fs.target`** any more — so `remote-fs.target` and everything ordered after it go ahead without the share. That is "nothing can wait for it". |
| `x-systemd.mount-timeout=` | Yes | How long systemd waits for the mount command before it marks the unit failed. Without it a dead NAS can stall boot for the default timeout (90 s) per mount, or forever with the `bg` rewrite. |
| `nofail` | Only if a missing share is acceptable | Boot continues without the mount, and the mount is no longer ordered before `remote-fs.target`. Fine for a "nice to have" share; wrong for the share your containers need. |
| `x-systemd.automount` | For shares from other hosts | Creates an `.automount` unit: an autofs trigger is mounted at boot (instantly), the real mount happens on first access. Boot never blocks on the other node. See the trap below. |
| `hard` (default) vs `soft` | `hard` for data you write | See [problem table](#5-common-problems) rows on NAS reboots. |

!!! warning "The automount trap with `rprivate` binds"
    With `x-systemd.automount`, what is mounted at `/mnt/nodeb/backup` at boot is an **autofs trigger**, not the share. A container started with an `rprivate` bind gets a copy of the trigger only. When something accesses it, the real NFS mount is created *on the host* on top of the trigger — and with `rprivate` it is never propagated into the container. Inside the container you see an empty directory or `Too many levels of symbolic links`. The same happens after every `x-systemd.idle-timeout` expiry. **Automount + Docker needs `:rslave` (Layer C)** and, ideally, the container should not start until the share is really mounted (Layer B on the path, plus Layer D).

!!! tip "Protect the empty mount point"
    While the share is **not** mounted, an app that writes to `/mnt/nas/media` writes to the root filesystem (Sonarr importing a season can fill `/` in minutes). Make the empty directory immutable once; mounting over it still works:
    ```bash
    sudo umount /mnt/nas/media          # only during a maintenance window
    sudo chattr +i /mnt/nas/media       # writes into the bare directory now fail
    sudo mount /mnt/nas/media
    lsattr -d /mnt/nas/media            # run while unmounted: shows ----i---------
    ```

### Layer B — make Docker wait for the mount (systemd drop-in)

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/10-wait-nas.conf >/dev/null <<'EOF'
[Unit]
# Docker containers bind-mount these paths: start dockerd only after they are mounted.
RequiresMountsFor=/mnt/nas/media
After=remote-fs.target
EOF
sudo systemctl daemon-reload
```

`RequiresMountsFor=` adds `Requires=` and `After=` on every mount unit needed to reach that path (here `mnt-nas-media.mount`). `After=remote-fs.target` additionally covers every other required network mount.

Verify — expected output names the path and the drop-in file:

```bash
systemctl show docker -p RequiresMountsFor -p DropInPaths
# RequiresMountsFor=/mnt/nas/media
# DropInPaths=/etc/systemd/system/docker.service.d/10-wait-nas.conf

systemctl list-dependencies docker --after | grep -E 'mnt-|remote-fs'
# ● ├─mnt-nas-media.mount
# ● ├─remote-fs.target
```

Know the trade-offs of `Requires=` before you rely on it:

- If the mount **fails** at boot, `docker.service` does **not start** (dependency failed). That is usually what you want for a media host — no containers is better than containers writing to the local disk — but it also stops containers that do not need the share. Put those on another host, or use `WantsMountsFor=` (systemd **256+**, i.e. Debian 13 / Proxmox VE 9; not in Debian 12 / PVE 8's systemd 252) to order without requiring.
- If you **explicitly stop or restart** the mount unit (`systemctl restart mnt-nas-media.mount`), systemd stops or restarts `docker.service` too — every container on the host. Plan NAS maintenance with that in mind.
- With a leftover `bg` (infinite timeout, 10000 retries) dockerd may wait a very long time. Remove `bg` first (Layer A).
- `RequiresMountsFor=` only works for paths systemd mounts. Proxmox storage under `/mnt/pve/<storage>` is mounted by `pvestatd`, not from fstab, so there is no unit to wait for at boot. Give Docker its own fstab mount of the export (and see the duplicate-mount row in the table).
- Docker in a **Proxmox LXC** with the share passed in as `mpX` from the node: the ordering problem moves to the node. The node must mount the share before the CT starts (fstab mount + `RequiresMountsFor=` in a drop-in for `pve-container@<vmid>.service`, or a CT startup delay), and the Docker drop-in inside the CT does not help.

### Layer C — `:rslave` bind propagation in Compose

```yaml
services:
  jellyfin:
    image: jellyfin/jellyfin:10.10.7          # pin a tag, not :latest
    restart: unless-stopped
    environment:
      - TZ=America/Edmonton
    volumes:
      # short syntax: source:target:options
      - /mnt/nas/media:/media:ro,rslave
      # long syntax, same thing, and refuses to auto-create a missing source
      - type: bind
        source: /mnt/nodeb/backup
        target: /backup
        bind:
          propagation: rslave
          create_host_path: false
```

With `rslave`, mounts and unmounts on the host *under or at* the bind source are propagated into the container (one way: nothing the container mounts leaks back to the host). A share that arrives late, an automount that fires, or a remount after a NAS reboot shows up in the running container without a restart.

Requirements and checks:

- The host side must be a shared mount. On systemd hosts `/` is `shared` by default: `findmnt -o TARGET,PROPAGATION /` → `/ shared`.
- Docker reports what it applied: `docker inspect jellyfin --format '{{range .Mounts}}{{.Source}}->{{.Destination}}:{{.Propagation}} {{end}}'` → `/mnt/nas/media->/media:rslave`.
- `rslave` is a safety net, not a fix for ordering: an app that scanned an empty `/media` at startup may already have marked the library as missing. Layer B is still needed.

### Layer D — optional per-container guard

Two options; use the entrypoint guard for anything that *processes* files (Tdarr, ffmpeg batch jobs), a healthcheck for everything else.

**Healthcheck** — flags the container `unhealthy`. Plain Docker does **not** restart unhealthy containers (only Swarm does); it is a signal for monitoring and for `depends_on: condition: service_healthy`.

```yaml
    healthcheck:
      # a marker file on the NAS share is better than "not empty": an empty but mounted share passes "not empty" checks
      test: ["CMD-SHELL", "test -e /media/.share-online || exit 1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 120s
```

**Entrypoint guard** — refuses to start, so the restart policy retries (with Docker's increasing restart delay) until the share is there:

```bash
#!/bin/sh
# guard-share.sh — exec the real command only if the share is mounted.
set -eu
MARKER="${SHARE_MARKER:-/media/.share-online}"
if ! timeout 10 test -e "$MARKER"; then
    echo "guard-share: $MARKER missing - share not visible, refusing to start" >&2
    exit 75   # EX_TEMPFAIL
fi
exec "$@"
```

Create the marker once on the NAS share: `touch /mnt/nas/media/.share-online`. `timeout` keeps a hung `hard` NFS mount from hanging the check.

### Layer E — watchdog timer (detect and repair one container)

A systemd timer on each Docker host checks every container/path pair, writes a metric, and restarts **only** the container that does not see its share — and never while it is busy.

```bash
sudo tee /usr/local/sbin/share-watchdog.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
# share-watchdog.sh — verify each container sees its network share; export a metric; restart only broken, idle containers.
# DRY_RUN=1 (default) only reports. Set DRY_RUN=0 in the service unit to allow restarts.
set -euo pipefail
DRY_RUN="${DRY_RUN:-1}"
PROM_DIR="${PROM_DIR:-/var/lib/prometheus/node-exporter}"
# container:path-inside-container:marker
CHECKS=(
  "jellyfin:/media:.share-online"
  "sonarr:/media:.share-online"
  "radarr:/media:.share-online"
  "tdarr:/media:.share-online"
)
tmp="$(mktemp)"
echo '# HELP container_share_visible 1 if the container sees the share marker, 0 if not.' >>"$tmp"
echo '# TYPE container_share_visible gauge' >>"$tmp"
for entry in "${CHECKS[@]}"; do
  IFS=: read -r c path marker <<<"$entry"
  if [[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" != "true" ]]; then
    continue
  fi
  if timeout 15 docker exec "$c" test -e "$path/$marker"; then
    ok=1
  else
    ok=0
  fi
  echo "container_share_visible{container=\"$c\",path=\"$path\"} $ok" >>"$tmp"
  logger -t share-watchdog "container=$c path=$path visible=$ok"
  if [[ "$ok" == 0 ]]; then
    # Busy = ffmpeg/ffprobe running inside (a stream being transcoded or a batch job). Do not interrupt it.
    if docker top "$c" -eo comm 2>/dev/null | grep -qE '^(ffmpeg|ffprobe)'; then
      logger -t share-watchdog "container=$c busy - restart skipped"
    elif [[ "$DRY_RUN" == 1 ]]; then
      logger -t share-watchdog "container=$c would restart (DRY_RUN=1)"
    else
      logger -t share-watchdog "container=$c restarting"
      docker restart "$c" >/dev/null
    fi
  fi
done
install -m 0644 "$tmp" "$PROM_DIR/container_share.prom"
rm -f "$tmp"
EOF
sudo chmod 0755 /usr/local/sbin/share-watchdog.sh

sudo tee /etc/systemd/system/share-watchdog.service >/dev/null <<'EOF'
[Unit]
Description=Check that containers see their network shares
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
Environment=DRY_RUN=1
ExecStart=/usr/local/sbin/share-watchdog.sh
EOF

sudo tee /etc/systemd/system/share-watchdog.timer >/dev/null <<'EOF'
[Unit]
Description=Run share-watchdog every 5 minutes
[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now share-watchdog.timer
```

Run it in `DRY_RUN=1` for a few days, read `journalctl -t share-watchdog`, then switch the service to `DRY_RUN=0`. A Jellyfin client that is direct-playing (no ffmpeg) is not detected as busy — if that matters, query Jellyfin's `/Sessions` API with an API key instead.

## 4. Audit checklist

Run on each Docker host. Replace `jellyfin`, `/media` and `/mnt/nas/media` with your names. Each line states the expected (good) result.

### Mounts

- [ ] `findmnt -t nfs,nfs4,cifs -o TARGET,SOURCE,FSTYPE,OPTIONS` — every share you expect is listed, once, with the options you set (`hard`, `vers=4.x`).
- [ ] `grep -E 'nfs|cifs' /etc/fstab` — every line has `_netdev`, a `x-systemd.mount-timeout=`, and **no** `bg`; `nofail` only on optional shares; cross-host shares use `x-systemd.automount`.
- [ ] `systemctl list-units --type=mount,automount --all | grep -E 'mnt-'` — every share unit `active mounted` (automount: `active running` / `waiting`); none `failed`.
- [ ] `findmnt -rn -t nfs,nfs4,cifs -o SOURCE | sort | uniq -d` — **no output**. Any line is one export mounted at two paths.
- [ ] `findmnt -o TARGET,PROPAGATION /` — `/ shared`.
- [ ] `journalctl -u mnt-nas-media.mount -b -o short-iso-precise` — note when it says `Mounted /mnt/nas/media`. No `mount error`, `Connection timed out` or `Stale file handle`.

### Docker start time vs mount time

```bash
U=$(systemd-escape -p --suffix=mount /mnt/nas/media)        # -> mnt-nas-media.mount
TZ=America/Edmonton systemctl show "$U" docker -p Id -p ActiveEnterTimestamp
for c in $(docker ps -q); do
  printf '%s %s\n' "$(docker inspect -f '{{.Name}}' "$c")" \
    "$(TZ=America/Edmonton date -d "$(docker inspect -f '{{.State.StartedAt}}' "$c")" '+%F %T %Z')"
done
systemd-analyze critical-chain docker.service               # mnt-nas-media.mount must appear in the chain
```

- [ ] The mount's `ActiveEnterTimestamp` is **before** docker's, and every container's `StartedAt` (UTC in Docker, converted above) is after the mount.

**Measured (incident)** on host A before the fix — the gap, in this output format (times shown as placeholders):

```text
Id=mnt-nas-media.mount
ActiveEnterTimestamp=<date> T MDT
Id=docker.service
ActiveEnterTimestamp=<date> T-3s MDT      <- docker 3 s before the mount: broken
```

### What the container really sees

- [ ] `docker exec jellyfin ls -A /media | head` — files listed. **Empty = broken** (or an empty share; use a marker file to tell them apart).
- [ ] `docker exec jellyfin cat /proc/self/mounts | awk '$2=="/media"'` — the **last** line has fs type `nfs4` / `cifs`. A single line with `ext4`/`xfs` (your root fs) means the container bound the empty mount point. Two lines (root fs, then nfs4) means the share arrived late and was propagated (`rslave` working).
- [ ] `docker inspect jellyfin --format '{{range .Mounts}}{{.Source}}->{{.Destination}}:{{.Propagation}} {{end}}'` — share binds show `rslave` (or `rshared`), not `rprivate`.

### Container configuration

- [ ] `docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}} {{.Config.Image}}' $(docker ps -aq)` — restart policy `unless-stopped` or `always` where intended; images pinned to a version tag, not `latest`.
- [ ] `docker exec <c> sh -c 'command -v ffmpeg ffprobe'` — the tools your jobs call are **inside** the container and on `PATH` (for example, the Jellyfin image ships its own build under `/usr/lib/jellyfin-ffmpeg/`, which may not be on `PATH`).
- [ ] `docker exec <c> id` and `docker inspect -f '{{.Config.Env}}' <c> | tr ' ' '\n' | grep -E 'PUID|PGID|TZ'` — UID/GID match the owner of the files on the share; `TZ` set.
- [ ] `docker exec <c> date` vs `date` on the host — same wall-clock time zone.

### Services and timers

- [ ] `systemctl --failed` — `0 loaded units listed.`
- [ ] `systemctl is-enabled docker share-watchdog.timer` and `systemctl is-active docker` — `enabled` / `active`. Enabled-but-inactive after boot means a dependency failed: `systemctl status docker` shows `Dependency failed`.
- [ ] `systemctl list-timers --all | grep share-watchdog` — `NEXT` within 5 minutes; `LAST` not empty.
- [ ] `systemctl show docker -p RequiresMountsFor -p DropInPaths` — the share path and `10-wait-nas.conf`.

### NFS behaviour on NAS outage

- [ ] `nfsstat -m` (or `findmnt -o TARGET,OPTIONS -t nfs4`) — `hard` on data shares. `soft`/`softerr` only on read-only, retry-safe data.
- [ ] `ps -eo pid,stat,wchan:32,cmd | awk '$2 ~ /D/'` — no processes stuck in `D` (uninterruptible) state.
- [ ] `ls /mnt/nas/media` — no `Stale file handle`.

## 5. Common problems

| Symptom | Cause | Check | Fix |
| :--- | :--- | :--- | :--- |
| Container `Up`, share empty after boot | dockerd (and its restart policies) started before the mount; the bind captured the empty mount-point directory; `rprivate` hides the later mount | Mount vs docker `ActiveEnterTimestamp`; `/proc/self/mounts` in the container shows the root fs at `/media` | Layer B drop-in, Layer C `:rslave`, restart the affected containers once |
| Share mounted on the host, not in the container | Host mount happened or was **re**mounted after the container started (NAS reboot, `mount -a`, automount fire, idle-timeout expiry) with `rprivate` | `findmnt /mnt/nas/media` on host shows nfs4; `docker inspect … Propagation` shows `rprivate` | `:rslave` on the bind; `docker restart <c>` for now |
| fstab line has `bg`; nothing waits for the share | systemd rewrites `bg` to `fg,nofail` + infinite timeout; `nofail` drops the ordering before `remote-fs.target` | `grep bg /etc/fstab`; `systemctl show mnt-nas-media.mount -p Before` lacks `remote-fs.target` | Remove `bg`; add `_netdev,x-systemd.mount-timeout=120`; `daemon-reload` |
| Boot hangs or a share is missing when another node is down | Cross-host boot dependency: host A mounts a share served by node B, which boots later (or is off) | `journalctl -u <unit> -b` shows timeouts; after a whole-site power loss both nodes boot together | `x-systemd.automount` + `:rslave` for that share; or order the VMs/CTs by Proxmox start order and startup delay |
| Processes hang, `D` state, `ls` never returns after the NAS rebooted | `hard` mount (default) retries indefinitely; every process touching the share blocks until the server answers | `ps -eo pid,stat,wchan:32,cmd`; `dmesg` shows `nfs: server … not responding, still trying` | Wait for the NAS — `hard` resumes on its own without data loss. Don't `kill -9` (it won't work). Last resort: `umount -f -l /mnt/nas/media` (then restart the containers) |
| Apps log `Input/output error` during NAS reboots; partial or corrupt files | `soft` mount: after `retrans` retries the kernel returns `EIO` to the app (`softerr` returns `ETIMEDOUT`) | `nfsstat -m` shows `soft`; app logs show EIO at the NAS reboot time | Use `hard` for data that is written; keep `soft` only where an error is safer than a hang (read-only, retried) |
| `Stale file handle` | The export or its file system was re-created / its ID changed on the NAS, or the NAS failed over | `ls /mnt/nas/media` → `Stale file handle` | `umount -l /mnt/nas/media && mount /mnt/nas/media`; with `:rslave` containers pick it up, otherwise restart them |
| Permission denied / files owned by `nobody` | UID/GID mismatch: container runs as `PUID`/`PGID` that does not own the files; NFS `root_squash` maps root to `nobody`; NFSv4 idmap domain mismatch | `docker exec <c> id`; `ls -ln /mnt/nas/media`; NAS export options | Set `PUID`/`PGID` to the share owner's numeric IDs; don't run as root against `root_squash` exports; same `Domain` in `/etc/idmapd.conf` on client and NAS; CIFS: `uid=`,`gid=` mount options |
| Permission denied after a NAS ACL change | NAS share/ACL now denies the UID, or the NFS client cached old attributes | Same file test on host vs container; NAS audit log | Fix the ACL on the NAS for the numeric UID; `mount -o remount` or restart the container |
| Container times and logs one hour (or 6–7 h) off | Container time zone is UTC (or the image default), the host is America/Edmonton | `docker exec <c> date` vs `date` | `TZ=America/Edmonton` in the environment, or bind `/etc/localtime:/etc/localtime:ro` |
| After `docker compose up` on one host the library is empty (NAS path changed) | Compose short syntax **auto-creates** a missing bind source as an empty directory owned by root; the old path no longer exists | `docker compose config` shows the resolved source; `ls -la <source>` is new and empty | Fix the path in `.env`/compose; use long syntax with `create_host_path: false`; `docker compose up -d` again |
| An empty directory appears where the mount point should be | `-v` / short syntax creates the source directory if it does not exist (`--mount` errors instead) | `stat <source>` creation time = container start | Use `--mount type=bind` or long syntax with `create_host_path: false` so a missing path fails loudly |
| Local disk filling up under `/mnt/nas/...` | App wrote into the mount point while the share was not mounted | `umount` then `du -sh /mnt/nas/media` (the underlying dir) | Move the data off, `chattr +i` the empty mount point, fix ordering |
| One share mounted twice (`/mnt/nas/media` and `/mnt/pve/nas`) | Proxmox storage + a manual fstab line for the same export | Duplicate-mount check in [§4 Mounts](#mounts) prints the export | Pick one path for apps; keep the other only for Proxmox, and document which one Docker uses |
| Container healthy, batch job fails on every file | The job's tool is not in the container or not on `PATH` (e.g. `ffprobe`), or the share is empty | `docker exec <c> sh -c 'command -v ffprobe'`; marker check | Call the tool by full path; make the job refuse to start when the share check fails (Layer D) |

## 6. Testing it — planned power-loss test

Test the way it fails: a full power cut of the NAS **and** the hosts together, not a polite reboot of one host.

1. **Before:** pick a quiet window, stop active transcodes/jobs, note the time (America/Edmonton). Record `findmnt -t nfs,nfs4,cifs`, `docker ps`, and the watchdog metric from each host.
2. **Cut power** to the NAS and Docker hosts (or the whole rack / UPS outlet group). Restore after 1 minute. Do not touch anything else.
3. **Pass criterion:** within **N = 15 minutes** of power being restored (adjust to your NAS's boot time), **every** container/path pair reports `container_share_visible == 1`, `systemctl --failed` is empty on every host, and **no manual action** was taken.
4. **Record** for each host:
   - NAS ready time (first successful mount in `journalctl -u <mount> -b`).
   - `ActiveEnterTimestamp` of each mount unit and `docker.service`; container `StartedAt` (converted to America/Edmonton).
   - The watchdog log (`journalctl -t share-watchdog -b`): any `visible=0`, restarts, or skipped-busy entries.
   - Pass/fail, time to all-green, and anything you had to touch (any manual step = fail).
5. **Variants** once the full test passes: NAS down for 10 minutes while hosts boot; node B left off (cross-host share); NAS reboot only, with hosts running (tests `hard` mounts and `:rslave`).

## 7. Monitoring — "container sees share" is the metric

`docker ps` says `Up` and the host says the share is mounted; neither proves the app sees its data. Export the check from inside the container instead.

- The watchdog writes `container_share_visible{container,path}` (1/0) for the node_exporter **textfile collector**. Start node_exporter with `--collector.textfile.directory=/var/lib/prometheus/node-exporter` (the Debian `prometheus-node-exporter` package already uses that directory).
- Alert rule (Prometheus):

```yaml
groups:
  - name: shares
    rules:
      - alert: ContainerShareNotVisible
        expr: container_share_visible == 0
        for: 10m
        labels: {severity: critical}
        annotations:
          summary: "{{ $labels.container }} cannot see {{ $labels.path }} on {{ $labels.instance }}"
      - alert: ContainerShareCheckStale
        expr: time() - node_textfile_mtime_seconds{file=~".*container_share.prom"} > 900
        labels: {severity: warning}
        annotations:
          summary: "share-watchdog has not run for 15 minutes on {{ $labels.instance }}"
```

- The second alert catches the watchdog itself not running (timer disabled, docker down) — otherwise the metric just stops updating and the last `1` looks fine.
- For a SIEM instead of Prometheus: the watchdog's `logger -t share-watchdog` lines go to the journal/syslog; forward them and alert on `visible=0`.

## 8. Lessons learned

- **"Running" is not "working".** Every layer that reported health (Docker, healthchecks, host mount monitoring) was green while users saw an empty library. Measure from inside the container, against a marker file.
- **A bind mount captures the past.** It binds whatever was at the path when the container started. Ordering (Layer B) plus propagation (Layer C) are both needed.
- **Defaults are the problem.** Docker's `rprivate` default and the packaged `docker.service` that only waits for the network are reasonable for local volumes and wrong for network shares.
- **`bg` is a pre-systemd habit.** Under systemd it becomes `nofail` with an infinite timeout — the opposite of what a dependent service needs.
- **Boot dependencies can cross hosts.** After a whole-site power loss everything boots at once; a share from another node is not there yet. Automount and `:rslave`, or explicit start order.
- **Tools that process files must check before they start.** An empty share turns a batch job into thousands of failures (or, worse, deletions of "missing" items). Refuse to start instead.
- **Test the real failure.** A full power cut with a written pass criterion; any manual step means the test failed.

## Related

- [Linux Service Failure Troubleshooting](linux-service-failure.md)
- [systemd services](../../platforms/linux/systemd.md)
- [Linux storage & LVM](../../platforms/linux/storage-lvm.md)
- [Proxmox VE](../../platforms/virtualization/proxmox.md)

## References

- [systemd.mount(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.mount.html) — fstab options, `bg` rewrite, `nofail`, `_netdev`, automount, network mount ordering
- [systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) — `RequiresMountsFor=`, `WantsMountsFor=` (v256), `Requires=` stop/restart behaviour
- [nfs(5)](https://man7.org/linux/man-pages/man5/nfs.5.html) — `hard`/`soft`/`softerr`, `bg`/`fg`
- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/) — propagation (`rprivate` default, `rslave`), `-v` vs `--mount` for missing paths
- [Compose file — services volumes](https://docs.docker.com/reference/compose-file/services/#volumes) — long syntax `bind.propagation`, `bind.create_host_path`
- [Docker restart policies](https://docs.docker.com/engine/containers/start-containers-automatically/)
- [Prometheus node_exporter textfile collector](https://github.com/prometheus/node_exporter#textfile-collector)
