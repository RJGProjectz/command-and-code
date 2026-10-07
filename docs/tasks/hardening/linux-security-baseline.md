---
title: Linux Security Baseline — CIS Benchmark & NIST CSF 2.0
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Assurance
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - cis-benchmark
  - nist-csf
  - baseline
  - hardening
  - linux
  - sysctl
  - sshd
  - pam
---

# Linux Security Baseline — CIS Benchmark & NIST CSF 2.0

Operational baseline hardening configurations for Linux servers (Ubuntu, Debian, RHEL, Rocky), directly aligned with the **CIS Distribution-Independent Linux Benchmark (Level 1 & Level 2)** and **NIST Cybersecurity Framework (CSF) 2.0** (`PR.PS-01`, `PR.AC-01`, `PR.DS-01`).

---

## 1. Compliance Alignment Matrix

| CIS Control | NIST CSF 2.0 | Configuration Target | Hardening Standard |
|:---|:---|:---|:---|
| **CIS 1.1** | `PR.PS-01` | Filesystem Modules | Disable unneeded legacy filesystems (`cramfs`, `freevxfs`, `jffs2`, `hfs`). |
| **CIS 3.2** | `PR.DS-01` | Network Stack (`sysctl`) | Disable IP forwarding, packet redirects, and source-routed packets; enable ASLR. |
| **CIS 5.2** | `PR.AC-01` | SSH Daemon (`sshd`) | Disable root login, enforce key authentication, limit auth attempts to 3. |
| **CIS 5.4** | `PR.AC-01` | PAM & Password Quality | Enforce minimum 14-char complexity and 5-attempt account lockout. |
| **CIS 6.1** | `PR.DS-01` | File Permissions | Enforce 0644 on `/etc/passwd`, 0000 on `/etc/shadow`, restrict SUID binaries. |

---

## 2. Kernel Runtime Hardening (`sysctl`)

Create `/etc/sysctl.d/99-cis-baseline.conf` to enforce kernel-level protections against network spoofing and memory exploitation:

```bash
cat << 'EOF' > /etc/sysctl.d/99-cis-baseline.conf
# CIS 3.1.1 - Disable IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# CIS 3.2.1 - Disable Packet Redirect Sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# CIS 3.2.2 - Reject ICMP Redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# CIS 3.2.3 - Reject Source Routed Packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# CIS 3.2.4 - Enable Reverse Path Filtering (Spoof Protection)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# CIS 3.2.5 - Log Suspicious Packets (Martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# CIS 3.2.8 - Enable TCP SYN Cookies (SYN Flood Defense)
net.ipv4.tcp_syncookies = 1

# CIS 1.5.1 - Enable Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# CIS 1.5.3 - Restrict Core Dumps for SUID Executables
fs.suid_dumpable = 0
EOF

# Apply sysctl settings immediately
sysctl --system
```

---

## 3. SSH Daemon Hardening (`sshd`)

Create `/etc/ssh/sshd_config.d/99-cis-hardening.conf` to enforce hardened transport security and eliminate credential brute-forcing:

```bash
cat << 'EOF' > /etc/ssh/sshd_config.d/99-cis-hardening.conf
# CIS 5.2.2 - Enforce SSH Protocol 2
Protocol 2

# CIS 5.2.4 - Disable Root Login
PermitRootLogin no

# CIS 5.2.5 - Restrict Authentication Attempts
MaxAuthTries 3

# CIS 5.2.8 - Disable Empty Passwords
PermitEmptyPasswords no

# CIS 5.2.11 - Enforce Idle Timeout (5 minutes)
ClientAliveInterval 300
ClientAliveCountMax 0

# CIS 5.2.13 - Disable X11 & Agent Forwarding
X11Forwarding no
AllowAgentForwarding no

# CIS 5.2.15 - Modern Cryptographic Ciphers & MACs
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
EOF

# Test configuration syntax before reloading daemon
sshd -t && systemctl reload sshd
```

---

## 4. File Permission Auditing & Correction

Enforce strict access permissions across security-critical authentication stores:

```bash
# Correct critical authentication file permissions
chown root:root /etc/passwd && chmod 644 /etc/passwd
chown root:root /etc/group && chmod 644 /etc/group
chown root:shadow /etc/shadow && chmod 000 /etc/shadow
chown root:shadow /etc/gshadow && chmod 000 /etc/gshadow

# Verify no world-writable files exist on the root partition
find / -xdev -type f -perm -0002 -exec ls -ld {} + 2>/dev/null
```

---

## 5. Verification Commands

```bash
# Verify ASLR status (expected: 2)
sysctl kernel.randomize_va_space

# Check active SSH configuration directives
sshd -T | grep -E "(permitrootlogin|maxauthtries|clientaliveinterval|x11forwarding)"

# Verify shadow file permissions (expected: ----------)
ls -l /etc/shadow
```
