---
title: Remote File Transfer — SCP, SFTP, rsync & WinRM
type: entry
platforms:
  - Linux
  - Windows
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Administration
  - Automation
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - scp
  - sftp
  - rsync
  - ssh
  - winrm
  - file-transfer
  - transfer
---

# Remote File Transfer — SCP, SFTP, rsync & WinRM

Production-ready syntax for transferring files, forensic artifacts, and backups securely between local workstations, remote servers, and isolated jump hosts.

---

## 1. Secure Copy Protocol (`scp`)

### Basic & Recursive Transfer
```bash
# Push local file to remote host
scp -P 22 ./payload.tar.gz user@10.10.10.50:/opt/staging/

# Pull remote file to current local directory
scp user@10.10.10.50:/var/log/audit/audit.log ./incident-audit.log

# Recursively transfer entire directory while preserving timestamps and permissions (-p)
scp -r -p ./configs/ admin@10.10.10.50:/etc/app/configs/
```

### Advanced Transfer Options
```bash
# Specify private SSH key identity file (-i) and non-standard port (-P)
scp -P 2222 -i ~/.ssh/prod_id_ed25519 ./report.pdf secops@10.10.10.50:/home/secops/

# Limit transfer bandwidth to 5000 Kbit/s to protect production links
scp -l 5000 ./database-dump.sql user@10.10.10.50:/backup/

# Transfer through a bastion/jump host (-J)
scp -J jumpuser@jump.internal:22 ./archive.tar.gz root@db.internal:/var/data/
```

---

## 2. Fast & Delta File Synchronization (`rsync`)

### Standard Synchronization Syntax
```bash
# Archive mode (-a: preserves permissions, symlinks, timestamps), compress (-z), progress (-P)
rsync -azP /var/www/html/ user@10.10.10.50:/var/www/html/

# Pull directory from remote server with dry-run (-n) verification first
rsync -azPn user@10.10.10.50:/var/log/nginx/ ./nginx-logs/
```

### Mirroring & Clean Deletion (`--delete`)
```bash
# Mirror directories exactly, removing files at destination that no longer exist at source
rsync -azP --delete /srv/data/ backup@10.10.10.50:/srv/data_mirror/

# Exclude unwanted patterns (.git, cache, temp logs)
rsync -azP --exclude '.git/' --exclude '*.tmp' --exclude 'node_modules/' ./src/ user@remote:/app/src/
```

### Custom SSH Ports & Key Authentication
```bash
# Pass custom SSH binary parameters via -e
rsync -azP -e "ssh -p 2222 -i ~/.ssh/admin_key" /etc/ssl/ certs@10.10.10.50:/etc/ssl/
```

---

## 3. Secure File Transfer Protocol (`sftp`)

### Interactive Session Navigation
```bash
# Connect using specified key and port
sftp -P 2222 -i ~/.ssh/id_rsa user@10.10.10.50

# Interactive Commands:
# get /remote/file.txt ./local/          # Download remote file
# put ./local/patch.tar.gz /opt/         # Upload local file
# mget /remote/*.log ./logs/             # Multiple download
# lls / lpwd / lcd                       # Local filesystem commands
# bye / exit                             # Terminate session
```

### Automated Batch Script Mode
```bash
# Execute scripted non-interactive SFTP batch instructions
cat << 'EOF' > sftp_batch.txt
cd /var/reports
mget *.csv ./incoming/
rm *.csv
bye
EOF

sftp -b sftp_batch.txt -i ~/.ssh/batch_key user@10.10.10.50
rm -f sftp_batch.txt
```

---

## 4. Windows File Transfer (WinRM & BITS)

### PowerShell Remoting (`Copy-Item -ToSession`)
Requires PowerShell Remoting (WinRM HTTPS / HTTP) enabled on the remote endpoint:

```powershell
# Establish remote session
$cred = Get-Credential
$session = New-PSSession -ComputerName "WIN-SRV01.corp.internal" -Credential $cred

# Push local installer to remote C:\Temp directory
Copy-Item -Path "C:\Software\Agent.msi" -Destination "C:\Temp\Agent.msi" -ToSession $session

# Collect remote event log file back to analyst workstation
Copy-Item -Path "C:\Windows\System32\Winevt\Logs\Security.evtx" -Destination "C:\Forensics\Security.evtx" -FromSession $session

# Always clean up remoting sessions
Remove-PSSession -Session $session
```

### Background Intelligent Transfer Service (BITS)
Resilient file transfer that survives network disconnections and throttle limits:

```powershell
# Asynchronous resilient download
$job = Start-BitsTransfer -Source "https://updates.internal/patch.msu" -Destination "C:\Staging\patch.msu" -Asynchronous -Priority High

# Monitor progress
Get-BitsTransfer -JobId $job.JobId

# Finalize completed transfer
Complete-BitsTransfer -BitsJob $job
```
