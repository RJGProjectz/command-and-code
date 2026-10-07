---
title: VMware ESXi CLI Forensics and Ransomware Hardening
type: entry
platforms:
  - VMware
  - Linux
languages:
  - Bash
  - PowerShell
tasks:
  - Hardening
  - Incident Response
  - Forensics
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - vmware
  - esxi
  - esxcli
  - ransomware
  - forensics
  - hardening
  - virtualization
---

# VMware ESXi CLI Forensics and Ransomware Hardening

Ransomware groups actively target VMware ESXi hypervisors directly (using variants like ESXiArgs, LockBit, and Akira) to encrypt virtual disks (`.vmdk`) across hundreds of guest machines simultaneously.

---

## 1. ESXi Incident Response & Live Triage

When an ESXi host exhibits abnormal CPU spikes, killed virtual machines, or active shell sessions, connect via SSH or physical Direct Console User Interface ($DCUI$):

```bash
# 1. Inspect running processes and detect ransomware encryptor binaries
esxcli system process list | grep -E "VMNAME|CMD|PID"

# Look for suspicious binaries executing out of /tmp, /var/tmp, or datastores:
ps -c | grep -E "encrypt|vmdk|sh"

# 2. Check active network sockets and incoming SSH connections
esxcli network ip connection list | grep "ESTABLISHED"

# 3. Check for recently terminated virtual machines (Ransomware terminates VMs to release VMDK locks)
tail -n 100 /var/log/vmkernel.log | grep -i "destroy"
tail -n 100 /var/log/hostd.log | grep -i "poweroff"

# 4. Check for modified files in datastores within the last 24 hours
find /vmfs/volumes/ -name "*.vmdk" -mtime -1 -ls
find /vmfs/volumes/ -name "*readme*" -o -name "*HOW_TO_DECRYPT*" -ls
```

---

## 2. Forensic Evidence Preservation

```bash
# 1. Preserve ESXi system and authentication logs
mkdir -p /vmfs/volumes/datastore1/Forensics_Export/
cp -r /var/log/ /vmfs/volumes/datastore1/Forensics_Export/logs_$(date +%Y%m%d)/

# 2. Check SSH key persistence in root profile
cat /etc/ssh/keys-root/authorized_keys

# 3. Inspect scheduled jobs (ESXi crontabs)
cat /var/spool/cron/crontabs/root
```

---

## 3. ESXi Hypervisor Hardening Protocols

### Disable SSH and Enforce Lockdown Mode
SSH should remain disabled by default on ESXi hypervisors. Enable it only during active maintenance windows.

```bash
# Disable SSH service immediately
esxcli system service set -s SSH -e false

# Query active Lockdown Mode status (Disabled, Normal, Strict)
# In Strict mode, DCUI is disabled and only vCenter can manage the host
vim-cmd -U dcui vimsvc/lockdownstatus
```

### Configure Centralized Remote Syslog (Tamper-Resistant Logging)
Ransomware attackers wipe `/var/log/` upon completion. Centralizing syslog to a SIEM ensures logs survive hypervisor wipeout:

```bash
# Set remote syslog server IP and port
esxcli system syslog config set --loghost="udp://10.0.10.50:514"

# Reload syslog daemon and verify connection
esxcli system syslog reload
esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true
```

### Restrict Management Network Access via Host Firewall

```bash
# Set default rule to drop incoming traffic
esxcli network firewall set --default-action=false --enabled=true

# Allow SSH and HTTPS only from dedicated management subnet (10.0.100.0/24)
esxcli network firewall ruleset set --ruleset-id=sshServer --allowed-all=false
esxcli network firewall ruleset allowedip add --ruleset-id=sshServer --ip-address="10.0.100.0/24"
esxcli network firewall ruleset set --ruleset-id=vSphereClient --allowed-all=false
esxcli network firewall ruleset allowedip add --ruleset-id=vSphereClient --ip-address="10.0.100.0/24"
```
