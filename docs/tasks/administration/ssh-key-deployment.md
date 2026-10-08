---
title: Administration — SSH Key Generation, Deployment & Best Practices
type: workflow
platforms:
  - Linux
  - Windows
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - ssh
  - ssh-keys
  - ed25519
  - authorized-keys
  - ssh-agent
  - proxyjump
  - bastion
  - hardening
---

# Administration — SSH Key Generation, Deployment & Best Practices

Asymmetric SSH key authentication replaces vulnerable password-based logins, mitigates brute-force exposure, and enables automated, auditable administrative access across hybrid infrastructure.

---

## 1. Conceptual Grounding: Client vs Server Key Architecture

Understanding key placement prevents inverted deployment errors:

- **Client Workstation (Origin)**: The system initiating the connection (e.g., Windows or macOS workstation).
    - **Private Key (`~/.ssh/id_ed25519`)**: Stays strictly on the client. It must never be copied, transmitted, or uploaded to remote systems. It cryptographically signs authentication challenges.
- **Remote Host (Destination)**: The target server or VM receiving the connection (e.g., Linux server).
    - **Public Key (`~/.ssh/id_ed25519.pub`)**: Placed onto the remote host inside `~/.ssh/authorized_keys`. The server uses this public key as a lock to verify challenge signatures without passwords.

---

## 2. Key Generation Standards & Algorithms

Always prefer modern elliptic curve cryptography (**Ed25519**) over legacy algorithms. Ed25519 keys offer superior cryptographic strength, constant-time execution (preventing side-channel timing attacks), and compact 256-bit signatures.

### Primary Standard: Ed25519 with Hardened KDF
```bash
# Generate Ed25519 key pair with 100 Key Derivation Function (KDF) rounds
ssh-keygen -t ed25519 -a 100 -C '<USER>@<WORKSTATION>' -f ~/.ssh/id_ed25519
```

- `-a 100`: Increases the brute-force resistance of the passphrase by executing 100 bcrypt key derivation rounds against the private key file.
- `-C '<USER>@<WORKSTATION>'`: Embedded comment identifying the owner and origin host.
- `-f ~/.ssh/id_ed25519`: Target path for private and public key files.

### Compatibility Fallback: RSA 4096-bit
For legacy appliances or older operating systems lacking Ed25519 support, use RSA with a minimum key length of 3072 or 4096 bits:

```bash
# Generate high-security RSA 4096-bit key pair
ssh-keygen -t rsa -b 4096 -a 100 -C '<USER>@<WORKSTATION>' -f ~/.ssh/id_rsa
```

### Hardware-Backed Security Keys (FIDO2 / U2F)
OpenSSH 8.2+ supports hardware security keys (e.g., YubiKey) where the private key never leaves the physical cryptographic token:

```bash
# Generate FIDO2 resident key (requires hardware token touch to authenticate)
ssh-keygen -t ed25519-sk -O resident -C '<USER>@yubikey'
```

### Windows Workstations (PowerShell)
Windows 10, 11, and Windows Server 2019+ include native OpenSSH client tools:

```powershell
# Windows: Generate Ed25519 key pair in user profile
ssh-keygen.exe -t ed25519 -a 100 -C "$($env:USERNAME)@$($env:COMPUTERNAME)" -f "$HOME\.ssh\id_ed25519"
```

---

## 3. Deploying Public Keys to Remote Hosts

The public key (`*.pub`) must be appended to the target user's `~/.ssh/authorized_keys` file on the remote server. Never transfer or expose the private key file.

### Linux / macOS Client: `ssh-copy-id`
```bash
# Standard SSH port (22)
ssh-copy-id -i ~/.ssh/id_ed25519.pub '<USER>@<TARGET_HOST>'

# Custom SSH port
ssh-copy-id -i ~/.ssh/id_ed25519.pub -p '<PORT>' '<USER>@<TARGET_HOST>'
```

### Windows Client: Stream & Set Permissions in One Pass
When `ssh-copy-id` is unavailable on Windows, stream the public key using PowerShell while establishing safe POSIX directory and file permissions in a single command:

```powershell
# Stream local public key to remote Linux host, ensure ~/.ssh exists (700) and authorized_keys (600)
Get-Content "$HOME\.ssh\id_ed25519.pub" | ssh -p '<PORT>' '<USER>@<TARGET_HOST>' "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

### Target: Windows OpenSSH Server
Windows OpenSSH handles public key placement based on account privilege:

1. **Standard Non-Admin User**: Place the public key in `C:\Users\<USER>\.ssh\authorized_keys`.
2. **Local Administrator User**: Windows OpenSSH redirects all members of the local `Administrators` group to a central file:
   - File location: `C:\ProgramData\ssh\administrators_authorized_keys`
   - Required ACL permissions (run in elevated PowerShell):

```powershell
# Set strict ACL permissions on Windows administrative authorized_keys
$AuthPath = "C:\ProgramData\ssh\administrators_authorized_keys"
icacls.exe $AuthPath /inheritance:r /grant "SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)"
```

---

## 4. Strict Permissions & Troubleshooting (`StrictModes`)

By default, OpenSSH enforces `StrictModes yes`. If files or parent directories have loose permissions (e.g., writable by group or other users), `sshd` **silently ignores** the `authorized_keys` file and falls back to password authentication without logging an error to the client.

### Linux Permissions Baseline

| Path | Required Mode | Ownership | Description |
| :--- | :--- | :--- | :--- |
| `/home/<USER>` | `755` or `750` | `<USER>:<USER>` | Home directory must NOT be writable by group or others (`chmod go-w`) |
| `~/.ssh` | `700` (`rwx------`) | `<USER>:<USER>` | User SSH directory |
| `~/.ssh/authorized_keys` | `600` (`rw-------`) | `<USER>:<USER>` | Authorized public keys |
| `~/.ssh/id_*` (Private) | `600` (`rw-------`) | `<USER>:<USER>` | Client private key |
| `~/.ssh/id_*.pub` (Public)| `644` (`rw-r--r--`) | `<USER>:<USER>` | Client public key |
| `~/.ssh/config` | `600` or `644` | `<USER>:<USER>` | Client SSH configuration |

### One-Line Permission Repair Script (Linux)
```bash
# Correct permissions for current user's SSH environment
chmod 700 ~/.ssh && \
  chmod 600 ~/.ssh/authorized_keys ~/.ssh/id_* 2>/dev/null; \
  chmod 644 ~/.ssh/*.pub ~/.ssh/known_hosts 2>/dev/null; \
  chmod go-w ~
```

### Windows Private Key ACL Hardening (PowerShell)
If the Windows OpenSSH client reports `"Permissions for id_ed25519 are too open"`, strip inherited permissions and grant access exclusively to your user account:

```powershell
# Restrict private key to current user only (remove inheritance, grant Full Control)
$Key = "$HOME\.ssh\id_ed25519"
icacls.exe $Key /reset
icacls.exe $Key /inheritance:r
icacls.exe $Key /grant:r "$($env:USERNAME):(F)"
```

---

## 5. SSH Agent & Keyring Integration

The SSH Authentication Agent stores decrypted private keys in memory so administrators enter their passphrase only once per workstation session.

### Linux / macOS: `ssh-agent`
```bash
# Start ssh-agent in current shell session
eval "$(ssh-agent -s)"

# Add private key with lifetime timeout (e.g., 8 hours)
ssh-add -t 8h ~/.ssh/id_ed25519

# List currently cached key fingerprints in agent
ssh-add -l

# Remove all keys from agent memory upon departure
ssh-add -D
```

### Windows: Native OpenSSH Agent Service
```powershell
# Ensure OpenSSH Authentication Agent service starts automatically
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent

# Load private key into agent
ssh-add.exe "$HOME\.ssh\id_ed25519"

# Verify cached identity
ssh-add.exe -l
```

### Security Warning: Agent Forwarding (`ForwardAgent`)
> [!WARNING]
> Never set `ForwardAgent yes` globally or when connecting to untrusted hosts. Anyone with root access on a target host can access the forwarded agent UNIX domain socket to authenticate as you on any other system while your session is active.
>
> **Best Practice**: Use **`ProxyJump`** instead. `ProxyJump` tunnels end-to-end encrypted TCP packets through a bastion host without exposing your SSH agent socket to the intermediate jump server.

---

## 6. Client Configuration Ergonomics (`~/.ssh/config`)

Managing multiple servers, jump hosts, and identity keys is streamlined using `~/.ssh/config`.

Create or edit `~/.ssh/config`:

```text
# Global defaults applied to all connections
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    IdentitiesOnly yes
    AddKeysToAgent yes

# Direct connection with dedicated key
Host web-prod
    HostName 192.168.10.50
    User opsadmin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_prod

# Dedicated VM / Lab Host
Host dev-vm
    HostName <TARGET_HOST>
    User <USER>
    IdentityFile ~/.ssh/id_ed25519

# Isolated host routed through a Bastion / Jump Server
Host db-internal
    HostName 10.0.5.25
    User dba
    IdentityFile ~/.ssh/id_ed25519_prod
    ProxyJump bastion.example.com

# Bastion configuration
Host bastion.example.com
    User jumpuser
    Port 22
    IdentityFile ~/.ssh/id_ed25519_bastion

# Lightning-fast connection multiplexing (reuses existing TCP socket)
Host cluster-*
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m
```

- `IdentitiesOnly yes`: Prevents `ssh` from offering every key loaded in `ssh-agent`, which prevents the common `"Received disconnect from host: Too many authentication failures"` error.
- `ProxyJump`: Routes connections transparently through an intermediate jump host.
- `ControlMaster auto`: Reuses an existing established TCP socket for subsequent SSH/SCP sessions, cutting connection time from hundreds of milliseconds to under 20ms.

### Client Configuration Troubleshooting & Traps

#### Trap 1: Environment Variables in Config Files
OpenSSH configuration parsers **do not** evaluate Windows or PowerShell environment variables (such as `$env:USERPROFILE` or `%USERPROFILE%`).
- **Incorrect**: `IdentityFile $env:USERPROFILE\.ssh\id_ed25519`
- **Correct**: Use the standard tilde shortcut `~` which OpenSSH natively evaluates across Windows, Linux, and macOS:
  ```text
  IdentityFile ~/.ssh/id_ed25519
  ```

#### Trap 2: Notepad Hidden `.txt` Extension (`No such host is known`)
When creating a config file with Windows Notepad, the editor often silently appends a `.txt` extension (`config.txt`). OpenSSH strictly looks for the extensionless file named `config`. If `config.txt` exists, OpenSSH ignores it, causing `ssh <ALIAS>` to attempt DNS resolution on the alias name and fail with `ssh: Could not resolve hostname <ALIAS>: No such host is known`.

```powershell
# Check if config was saved with a hidden .txt extension
Get-ChildItem -Path "$HOME\.ssh\config*"

# Fix: Rename config.txt to extensionless config
if (Test-Path "$HOME\.ssh\config.txt") {
    Rename-Item -Path "$HOME\.ssh\config.txt" -NewName "config"
}
```

---

## 7. Key Lockdown & Automation Privileges

For service accounts, backup jobs, and automated CI/CD pipelines, restrict the public key directly in `~/.ssh/authorized_keys` to enforce the principle of least privilege.

Prepend restriction directives to the beginning of the public key line:

```text
from="10.10.10.0/24,192.168.1.50",command="/usr/local/bin/backup-sync.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... backup-service-account
```

| Directive | Security Effect |
| :--- | :--- |
| `command="/path/to/script"` | Ignores whatever command the client requests; forces execution of only this specific script |
| `from="<IP_OR_CIDR>"` | Restricts key usage to connections originating from specified IP addresses or subnets |
| `no-pty` | Disallows allocation of an interactive pseudo-terminal (shell access blocked) |
| `no-port-forwarding` | Blocks local and remote TCP port forwarding (`-L`, `-R`, `-D`) |
| `no-agent-forwarding` | Prevents the client from forwarding an authentication agent |
| `no-X11-forwarding` | Blocks graphical X11 display forwarding |

---

## 8. Zero-Lockout Safe Cutover Checklist

Before permanently disabling password authentication on a remote production server, execute this systematic migration checklist:

1. **Step 1: Test Key Authentication in a Secondary Terminal**
   Do not close your current active administrative shell. Open a new, separate terminal and test key-based authentication explicitly:
   ```bash
   ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o PreferredAuthentications=publickey '<USER>@<TARGET_HOST>'
   ```

2. **Step 2: Create Modular Hardening Drop-in**
   On the remote host, create `/etc/ssh/sshd_config.d/99-disable-passwords.conf`:
   ```text
   # Disable password authentication and enforce public keys
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PubkeyAuthentication yes
   PermitRootLogin prohibit-password
   ```

3. **Step 3: Validate Daemon Syntax**
   Test configuration syntax before reloading:
   ```bash
   sudo sshd -t
   ```

4. **Step 4: Safely Reload the Daemon**
   Reload the service (which does not terminate existing established connections):
   ```bash
   sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
   ```

5. **Step 5: Verify Password Rejection**
   In a third terminal window, verify that password-based logins are actively refused:
   ```bash
   ssh -o PubkeyAuthentication=no '<USER>@<TARGET_HOST>'
   # Expected result: Permission denied (publickey).
   ```

---

## Related Guides

- [Linux SSH Daemon Configuration & Security Baseline](../../platforms/linux/ssh.md)
- [Fundamentals — SSH Key Architecture & Cryptography Baselines](../../fundamentals/identity/ssh-keys.md)
- [Remote File Transfer — SCP, SFTP, rsync & WinRM](remote-file-transfer.md)
- [Windows Remote Access (WinRM & OpenSSH)](../../platforms/windows/winrm-openssh.md)
