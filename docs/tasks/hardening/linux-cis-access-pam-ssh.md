---
title: Linux CIS Benchmark — Access Control, PAM & SSH Hardening
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
  - pam
  - sshd
  - faillock
  - ciphers
  - permissions
---

# Linux CIS Benchmark — Access Control, PAM & SSH Hardening

Network exposure, authentication credentials, and file permissions form the primary attack surface on enterprise Linux endpoints. **CIS Sections 3, 5, and 6** enforce cryptographic SSH ciphers, brute-force lockout thresholds via Pluggable Authentication Modules (PAM), and strict file permission ownership standards.

---

## 1. CIS Section 3.4 & 3.5: Host Firewall & Protocol Blacklisting

### Network Protocol Blacklisting (`/etc/modprobe.d/cis-net.conf`)

Adversaries abuse rare or unmonitored transport protocols (DCCP, SCTP, RDS, TIPC) for covert egress and kernel exploitation:

```bash
sudo tee /etc/modprobe.d/cis-net.conf << 'EOF'
# CIS 3.4.1 - 3.4.4: Blacklist non-essential network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
```

### Host Firewall Default-Deny Baseline (`ufw` / `nftables`)

```bash
# CIS 3.5: Enforce default-deny inbound posture via UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed

# Allow SSH strictly from administrative jump-box or subnets
sudo ufw allow in on eth0 proto tcp to any port 22

# Enable firewall stateful tracking
sudo ufw enable
sudo ufw status verbose
```

---

## 2. CIS Section 5.3: PAM Password Quality & Account Lockout

Configure Pluggable Authentication Modules (PAM) to enforce complex passwords and temporary account lockouts upon repeated invalid attempts.

### Password Complexity (`/etc/security/pwquality.conf`)

```bash
sudo tee /etc/security/pwquality.conf << 'EOF'
# CIS Section 5.3.1: Password Quality Baseline
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 3
gecoscheck = 1
maxrepeat = 3
EOF
```

### Account Lockout Thresholds (`pam_faillock`)

Prevent automated SSH and local credential stuffing by locking accounts after 5 failures:

```bash
# Append to /etc/security/faillock.conf
sudo tee /etc/security/faillock.conf << 'EOF'
# CIS Section 5.3.2: Account Lockout Baseline
dir = /var/run/faillock
audit
silent
deny = 5
fail_interval = 900
unlock_time = 900
EOF
```

---

## 3. CIS Section 5.2: Hardened SSH Server Configuration (`sshd`)

Enforce modern cryptographic ciphers, disable unauthenticated forwarding, and eliminate root login in `/etc/ssh/sshd_config.d/99-cis-hardening.conf`:

```bash
sudo tee /etc/ssh/sshd_config.d/99-cis-hardening.conf << 'EOF'
## -----------------------------------------------------------------------------
## CIS Section 5.2: OpenSSH Server Hardening Baseline
## -----------------------------------------------------------------------------

# CIS 5.2.2 - Protocol 2 only
Protocol 2

# CIS 5.2.4 - Disable Root Login
PermitRootLogin no

# CIS 5.2.5 - Restrict Max Authentication Attempts
MaxAuthTries 3

# CIS 5.2.8 - Forbid Empty Passwords
PermitEmptyPasswords no

# CIS 5.2.11 - Idle Session Timeout (5 minutes)
ClientAliveInterval 300
ClientAliveCountMax 0

# CIS 5.2.13 & 5.2.14 - Disable X11 and Agent Forwarding
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no

# CIS 5.2.15 - Enforce Pre-Logon Legal Warning Banner
Banner /etc/issue.net

# CIS 5.2.17 - Restrict Cryptographic Ciphers (No CBC ciphers)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

# CIS 5.2.18 - Restrict Message Authentication Codes (MACs) (ETM only)
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# CIS 5.2.19 - Restrict Key Exchange Algorithms (KexAlgorithms)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF

# Validate syntax before reloading service
sudo sshd -t && sudo systemctl reload sshd
```

---

## 4. CIS Section 5.1: Cron & Task Scheduler Security

Restricting permissions on `/etc/cron*` ensures non-root processes cannot schedule malicious persistent jobs:

```bash
# CIS Section 5.1: Enforce strict root ownership and permissions on cron files
sudo chown root:root /etc/crontab
sudo chmod 0600 /etc/crontab

sudo chown root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
sudo chmod 0700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# Restrict cron / at access to authorized users
sudo rm -f /etc/cron.deny /etc/at.deny
echo "root" | sudo tee /etc/cron.allow > /dev/null
echo "root" | sudo tee /etc/at.allow > /dev/null
sudo chmod 0640 /etc/cron.allow /etc/at.allow
```

---

## 5. CIS Section 6: System Maintenance & Permissions Verification

### File Permissions Integrity Baseline

```bash
# CIS Section 6.1: Enforce standard permissions on critical identity files
sudo chmod 0644 /etc/passwd && sudo chown root:root /etc/passwd
sudo chmod 0000 /etc/shadow && sudo chown root:root /etc/shadow
sudo chmod 0000 /etc/gshadow && sudo chown root:root /etc/gshadow
sudo chmod 0644 /etc/group && sudo chown root:root /etc/group
```

### Auditing Unowned and SUID Binaries

```bash
# 1. Scan for unowned or ungrouped files (potential orphaned attacker artifacts)
sudo find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# 2. Audit all SUID binaries across local filesystems
sudo find / -xdev -perm -4000 -type f 2>/dev/null

# 3. Check for duplicate UIDs in /etc/passwd
cut -d: -f3 /etc/passwd | sort -n | uniq -d
```
