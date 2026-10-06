---
title: Linux SSH
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Hardening, Administration]
category: Remote Access
tags: [ssh, sshd, authorized_keys, sshd_config, persistence, hardening, remote access]
aliases: [ssh service status, ssh process check, ssh config location, authorized keys, ssh keys persistence, sshd -T, disable root login, ssh hardening]
difficulty: basic
verified: true
last_verified: 2026-10-06
---

# Linux SSH

A systematic guide to auditing, troubleshooting, configuring, and hardening OpenSSH on Linux systems.

---

## 1. Check Process, Service & Socket State

Always establish whether the SSH daemon is currently active, which PID owns it, and which interfaces and ports are open before inspecting files or modifying configurations.

### Daemon and Process Status

```bash
# Check systemd service state (unit is 'ssh' on Debian/Ubuntu, 'sshd' on RHEL/CentOS)
systemctl status ssh --no-pager 2>/dev/null || systemctl status sshd --no-pager

# Check if sshd process is currently running and inspect command line
pgrep -a sshd
```

### Listening Sockets and Ports

```bash
# Verify which IP addresses and ports sshd is listening on (default TCP 22)
sudo ss -tulpn | grep -E ':(22|ssh)\b'
```

### Active Connected Sessions

```bash
# View interactive user sessions logged into the host
who
w

# Inspect all established inbound SSH connections and remote client IPs
sudo ss -tnp state established '( sport = :22 )'
```

---

## 2. Known Locations & Key Filesystem Paths

Quick reference of standard file paths for OpenSSH server binaries, configuration drop-ins, host keys, user key stores, and authentication logs:

| Component | Standard Path | Purpose / Description |
| :--- | :--- | :--- |
| **Server Binary** | `/usr/sbin/sshd` | OpenSSH daemon executable |
| **Client Binary** | `/usr/bin/ssh` | OpenSSH client executable |
| **Main Config** | `/etc/ssh/sshd_config` | Primary server configuration file |
| **Config Drop-ins** | `/etc/ssh/sshd_config.d/*.conf` | Modular configuration files (Debian, Ubuntu, RHEL 9+) |
| **Client Config** | `/etc/ssh/ssh_config`, `~/.ssh/config` | System-wide and per-user client configurations |
| **Host Keys** | `/etc/ssh/ssh_host_*_key`, `*.pub` | Server identity keys (Ed25519, RSA, ECDSA) |
| **User Authorized Keys** | `~/.ssh/authorized_keys` | Public keys permitted to authenticate as that user |
| **Known Hosts** | `~/.ssh/known_hosts` | Cached host fingerprints for outbound client connections |
| **Auth Log (Debian/Ubuntu)** | `/var/log/auth.log` | Authentication events and accepted/failed logins |
| **Auth Log (RHEL/CentOS)** | `/var/log/secure` | Authentication events and accepted/failed logins |
| **Systemd Journal** | `journalctl -u ssh` (or `sshd`) | Real-time systemd service and connection logs |

---

## 3. Configuration Inspection & Syntax Testing

Never edit configuration files blind or restart a remote SSH daemon without testing configuration syntax first.

### Print Effective Runtime Configuration

The `-T` flag outputs the complete evaluated server configuration actually in force, incorporating all drop-ins and default parameters:

```bash
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|port |allowusers|allowgroups'
```

### Pre-Flight Syntax Validation

Always test your configuration syntax before restarting or reloading the daemon — a syntax error can lock administrators out of the host:

```bash
# Test configuration syntax without restarting (returns exit code 0 if valid)
sudo sshd -t

# If valid, safely reload daemon without dropping existing active connections
sudo sshd -t && sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
```

---

## 4. Key & Authentication Auditing

Auditing authorized keys across all local accounts is essential for verifying access and hunting persistence ([T1098.004](https://attack.mitre.org/techniques/T1098/004/)).

### Find authorized keys

```bash
# Locate all authorized_keys files across root and user home directories
sudo find / -xdev -name 'authorized_keys*' -type f -exec ls -l {} \; 2>/dev/null

# Print all authorized keys with their associated file paths
sudo sh -c 'awk "{print FILENAME\": \"\$0}" /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null'
```

### Public Key Fingerprints

Calculate key fingerprints to correlate with authentication logs:

```bash
ssh-keygen -lf '/home/<USER>/.ssh/authorized_keys'
```

### Audit Recent Logins

```bash
# Review recent accepted logins from auth logs
sudo grep -E 'Accepted (publickey|password)' /var/log/auth.log 2>/dev/null || sudo grep -E 'Accepted (publickey|password)' /var/log/secure

# Query systemd journal for accepted connections over the past 7 days
journalctl -u ssh --since "-7d" 2>/dev/null || journalctl -u sshd --since "-7d" | grep Accepted
```

---

## 5. Security Hardening Baseline

Deploy modular drop-in configurations to enforce modern cryptographic standards and disable password and root logins.

Create `/etc/ssh/sshd_config.d/10-hardening.conf`:

```text
# /etc/ssh/sshd_config.d/10-hardening.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

Validate and safely apply changes:

```bash
sudo sshd -t && (sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd)
```

---

## 6. Client-Side Diagnostics & Connection Debugging

When investigating connectivity or authentication failures from the client side:

```bash
# Connect with maximum verbosity (shows handshake, cipher exchange, and offered keys)
ssh -vvv user@host

# Test password authentication specifically, ignoring local SSH agent keys
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@host

# Connect specifying an explicit identity file
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes user@host
```

---

## Related

- [Linux Logs](logs.md#failed-ssh-logins)
- [Linux Troubleshooting Commands](troubleshooting.md)
- [Account Compromise Workflow](../../tasks/incident-response/account-compromise.md)

## Sources

- [sshd_config(5)](https://man.openbsd.org/sshd_config)
- [sshd(8)](https://man.openbsd.org/sshd)
