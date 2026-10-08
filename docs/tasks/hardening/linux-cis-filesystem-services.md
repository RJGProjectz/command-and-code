---
title: Linux CIS Benchmark — Filesystem Integrity & Service Hardening
type: workflow
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Assurance
  - Administration
verified: true
last_verified: 2026-10-08
difficulty: advanced
tags:
  - cis-benchmark
  - linux-hardening
  - filesystem-partitions
  - legacy-services
  - chrony
  - sticky-bit
  - core-dumps
---

# Linux CIS Benchmark — Filesystem Integrity & Service Hardening

The **CIS Distribution-Independent Linux Benchmark** begins with foundational operating system integrity. **Section 1 (Initial Setup)** enforces partition-level isolation to prevent denial-of-service and unprivileged binary execution, while **Section 2 (Services)** eliminates legacy, unencrypted, and unnecessary daemons that expand endpoint attack surface.

---

## 1. CIS Section 1.1: Filesystem Partitioning & Mount Options

Partition isolation confines volatile, world-writable directories to dedicated volumes mounted with non-executable and non-SUID restrictions.

```mermaid
graph TD
    Root[/ Root Partition] --> P1[/tmp: nodev, nosuid, noexec]
    Root --> P2[/var/tmp: nodev, nosuid, noexec]
    Root --> P3[/var/log: nodev, nosuid, noexec]
    Root --> P4[/var/log/audit: nodev, nosuid, noexec]
    Root --> P5[/home: nodev, nosuid]

    P1 & P2 --> Block[Blocks Malicious Script Execution]
    P3 & P4 --> Protect[Prevents Log DoS Exhaustion]
```

### Partition Hardening Matrix

| CIS ID | Target Mount Point | Recommended Mount Options | Threat Mitigated |
| :--- | :--- | :--- | :--- |
| **1.1.2** | `/tmp` | `nodev,nosuid,noexec` | Prevents executing dropped binaries or SUID escalation from `/tmp` |
| **1.1.4** | `/var/tmp` | `nodev,nosuid,noexec` | Prevents secondary staging execution |
| **1.1.6** | `/var` | `nodev,nosuid` | Prevents device node creation in spool and application directories |
| **1.1.8** | `/var/log` | `nodev,nosuid,noexec` | Prevents tampering and unprivileged code execution from log paths |
| **1.1.10** | `/var/log/audit` | `nodev,nosuid,noexec` | Protects kernel audit logs from disk exhaustion and corruption |
| **1.1.12** | `/home` | `nodev,nosuid` | Prevents users from introducing SUID binaries into user directories |

### Configuring `/etc/fstab` Mount Options

```bash
# Example /etc/fstab hardened entries
# Ensure partitions are dedicated volumes or tmpfs mounts
tmpfs                   /tmp            tmpfs   defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0
/tmp                    /var/tmp        none    bind,rw,nosuid,nodev,noexec                      0 0
UUID=xxx-var-log        /var/log        ext4    defaults,rw,nosuid,nodev,noexec                  0 2
UUID=xxx-audit-log      /var/log/audit  ext4    defaults,rw,nosuid,nodev,noexec                  0 2
UUID=xxx-home           /home           ext4    defaults,rw,nosuid,nodev                         0 2

# Remount active partitions to enforce immediately
mount -o remount,nodev,nosuid,noexec /tmp
mount -o remount,nodev,nosuid,noexec /var/tmp
```

---

## 2. CIS Section 1.1.1: Legacy & Unused Filesystem Module Blacklisting

Adversaries exploit legacy or non-standard filesystem drivers to trigger kernel memory corruptions. CIS mandates blacklisting unneeded filesystem modules:

```bash
# Create /etc/modprobe.d/cis-filesystems.conf
cat << 'EOF' > /etc/modprobe.d/cis-filesystems.conf
# CIS 1.1.1.1 - 1.1.1.8: Disable unneeded filesystem kernel modules
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

# Unload currently active modules
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
    rmmod "$mod" 2>/dev/null || true
done
```

---

## 3. CIS Section 1.5: Core Dumps & ASLR Hardening

Restricting core dumps prevents unprivileged users from extracting credentials, cryptographic keys, or sensitive application memory:

```bash
# 1. Disable core dumps in /etc/security/limits.d/99-cis-limits.conf
cat << 'EOF' > /etc/security/limits.d/99-cis-limits.conf
# CIS 1.5.1: Restrict core dumps for all users
* hard core 0
* soft core 0
EOF

# 2. Enforce kernel restrictions via sysctl
cat << 'EOF' > /etc/sysctl.d/99-cis-process.conf
# CIS 1.5.2: Restrict SUID core dumps
fs.suid_dumpable = 0

# CIS 1.5.3: Enable Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# CIS 1.5.4: Restrict ptrace process inspection to root / parent
kernel.yama.ptrace_scope = 1
EOF

sysctl --system
```

---

## 4. CIS Section 1.1.21: Sticky Bit Verification on World-Writable Directories

A sticky bit prevents users from deleting or renaming files owned by other users in shared world-writable directories (e.g., `/tmp`, `/var/tmp`):

```bash
# Scan and enforce sticky bit on all world-writable directories across the system
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | while read -r dir; do
    echo "[REMEDIATING] Setting sticky bit on: $dir"
    chmod +t "$dir"
done
```

---

## 5. CIS Section 2: Services & Daemon Elimination

Eliminate legacy network daemons and unencrypted management protocols that introduce critical vulnerability exposure:

```bash
# List of non-compliant daemons according to CIS Section 2.1 & 2.2
LEGACY_SERVICES=(
    "xinetd"
    "nis"
    "rsh-client"
    "rsh-redone-client"
    "talk"
    "telnet"
    "tftp"
    "tftpd-hpa"
    "avahi-daemon"
    "cups"
    "isc-dhcp-server"
    "bind9"
    "snmpd"
)

echo "[CIS Section 2] Disabling legacy services..."
for svc in "${LEGACY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  [STOPPING] $svc"
        systemctl stop "$svc" 2>/dev/null || true
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        echo "  [DISABLING] $svc"
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
    fi
done
```

### Time Synchronization Enforcement (Chrony / systemd-timesyncd)

Accurate time synchronization is mandatory for correlating security telemetry and investigating intrusions:

```bash
# Verify chrony status and configured time sources
if command -v chronyc >/dev/null 2>&1; then
    chronyc tracking
    chronyc sources
elif command -v timedatectl >/dev/null 2>&1; then
    timedatectl status
fi
```
