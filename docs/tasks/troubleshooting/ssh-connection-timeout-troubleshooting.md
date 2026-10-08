---
title: SSH Connection Timeouts, Session Freezes & Host Sleep Drops
type: workflow
platforms:
  - Linux
  - Windows
languages:
  - Bash
  - PowerShell
tasks:
  - Troubleshooting
  - Administration
verified: true
last_verified: 2026-10-08
difficulty: intermediate
tags:
  - ssh
  - ssh-timeout
  - sshd
  - networkmanager
  - tlp
  - udev
  - tmout
  - keepalive
  - power-management
---

# SSH Connection Timeouts, Session Freezes & Host Sleep Drops

**Symptom:** an established SSH terminal session suddenly freezes, disconnects after a period of inactivity, or drops when the remote machine or virtual machine enters a low-power or suspend state.

---

## 1. Interactive Diagnostic Decision Tree

<div class="cc-tree" data-title="SSH Timeout Diagnostic Flow" markdown>

<div class="cc-node cc-node--root" data-id="step-session-check" markdown>

#### Step 1: Active Connection & Established Session Inspection

Inspect active terminal users and verify whether the TCP socket on port 22 is still in an established state on the remote host:

```bash
# Check logged-in user terminals and idle times
who
w

# Inspect established inbound SSH TCP connections and client IPs
sudo ss -tnp state established '( sport = :22 )'
```

**What is the behavior of the connection drop?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-power-sleep">Host stops responding completely (Sleep/Suspend)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-nic-powersave">Drops only over Wi-Fi / Laptop battery (NIC Power Save)</button>
<button type="button" class="cc-branch-btn" data-next="step-shell-tmout">Drops cleanly with "timed out" after exact idle minutes (TMOUT)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset" data-next="step-keepalive">Session silently freezes without error message (NAT / Conntrack)</button>
</div>

</div>

<div class="cc-node" data-id="step-power-sleep" markdown>

#### Step 2: Systemd Sleep & Suspend Targets

If the target host is a laptop, desktop workstation, or virtual machine, systemd or desktop power managers may suspend the machine after user inactivity, killing network interfaces.

Check and mask all systemd sleep and suspend targets:

```bash
# Mask all sleep and hibernation targets to prevent system sleep
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# Disable power-profiles-daemon if overriding server availability
sudo systemctl stop power-profiles-daemon 2>/dev/null || true
sudo systemctl disable power-profiles-daemon 2>/dev/null || true
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ Fixed: Host stays awake</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-nic-powersave">Still dropping: Check NIC Power Saving</button>
</div>

</div>

<div class="cc-node" data-id="step-nic-powersave" markdown>

#### Step 3: Network Adapter & Wi-Fi Power Management

Linux power managers (NetworkManager, TLP, PCIe ASPM) aggressively power down wireless adapters or PCI network controllers during idle periods.

1. **Check device runtime power status:**
```bash
cat /sys/class/net/*/device/power/control
```
*(If output shows `auto`, the kernel is actively sleeping the network card during idle).*

2. **Force persistent network device power (`on`):**
```bash
# Create a udev rule to prevent the kernel from suspending network interfaces
sudo tee /etc/udev/rules.d/99-disable-network-sleep.rules << 'EOF'
ACTION=="add", SUBSYSTEM=="net", KERNEL=="*", ATTR{power/control}="on"
EOF

# Reload and trigger udev rules immediately
sudo udevadm control --reload-rules && sudo udevadm trigger
```

3. **Disable NetworkManager Wi-Fi Power Saving:**
```bash
# Create NetworkManager override drop-in
sudo tee /etc/NetworkManager/conf.d/default-wifi-powersave-on.conf << 'EOF'
[connection]
wifi.powersave = 2
EOF

sudo systemctl restart NetworkManager
```
*(Note: Value `2` disables powersave; `3` enables powersave).*

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ Fixed: Interface remains online</button>
<button type="button" class="cc-branch-btn" data-next="step-shell-tmout">Still dropping: Check Shell TMOUT</button>
</div>

</div>

<div class="cc-node" data-id="step-shell-tmout" markdown>

#### Step 4: Shell Inactivity Auto-Logout (`TMOUT`)

If sessions terminate cleanly after an exact duration (e.g., 300 seconds) with a message like `timed out waiting for input: auto-logout`, the bash shell has an active `$TMOUT` variable enforced in global profiles:

```bash
# Search for TMOUT definitions across global and user profiles
grep -rn "TMOUT" /etc/profile /etc/profile.d/ /etc/bash.bashrc ~/.bashrc 2>/dev/null
```

**Remediation:** Remove or adjust the `TMOUT` export in `/etc/profile.d/` or `/etc/bash.bashrc`.

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ Fixed: TMOUT variable adjusted</button>
<button type="button" class="cc-branch-btn" data-next="step-keepalive">Still dropping: Check SSH KeepAlives</button>
</div>

</div>

<div class="cc-node" data-id="step-keepalive" markdown>

#### Step 5: SSH Daemon & Client KeepAlive Tuning

Stateful firewalls, cloud NAT gateways, and residential routers silently drop idle TCP connection tracking entries after 5 to 15 minutes of silence without sending a TCP RST packet, causing the SSH terminal to freeze.

**Server-Side Fix (`/etc/ssh/sshd_config.d/99-keepalive.conf`):**
```bash
sudo tee /etc/ssh/sshd_config.d/99-keepalive.conf << 'EOF'
# Send null packet every 60 seconds to keep firewall state table open
ClientAliveInterval 60
# Terminate session only after 3 consecutive failed probes (3 minutes dead)
ClientAliveCountMax 3
# Enable TCP-level keepalive probes
TCPKeepAlive yes
EOF

# Validate syntax and reload daemon
sudo sshd -t && (sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd)
```

**Client-Side Fix (`~/.ssh/config` on Windows or Linux Client):**
```text
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    IPQoS throughput
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ Fixed: Heartbeats keep connection alive</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset" data-next="step-session-check">↺ Restart Diagnostic Flow</button>
</div>

</div>

<div class="cc-node cc-node--leaf" data-id="step-resolved" markdown>

#### Issue Resolved
The underlying cause of the SSH disconnect has been remediated. The connection is now protected against OS sleep, NIC powersave, shell auto-logouts, and firewall state drops.

</div>

</div>

---

## 2. Root Cause Breakdown & Remediation Matrix

| Root Cause | Diagnostic Indicator | Primary Fix Location | Persistent Remediation Command |
| :--- | :--- | :--- | :--- |
| **System Sleep / Suspend** | Target VM/host stops responding to ping; SSH drops during idle | systemd targets | `sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target` |
| **Power Daemon Overrides** | `power-profiles-daemon` or TLP powers down peripherals | System services | `sudo systemctl stop power-profiles-daemon && sudo systemctl disable power-profiles-daemon` |
| **Wi-Fi Power Management** | Connection drops when Wi-Fi adapter sleeps | NetworkManager | In `/etc/NetworkManager/conf.d/default-wifi-powersave-on.conf`: `wifi.powersave = 2` |
| **Kernel Device Sleep** | `/sys/class/net/*/device/power/control` shows `auto` | udev rules | In `/etc/udev/rules.d/99-disable-network-sleep.rules`: `ATTR{power/control}="on"` |
| **Shell Idle Timeout** | Session exits with `timed out waiting for input` | Profile scripts | `grep -rn "TMOUT" /etc/profile /etc/profile.d/` |
| **Stateful NAT Drop** | Terminal freezes; typing produces no characters | SSH config | Set `ClientAliveInterval 60` in `sshd_config` and `ServerAliveInterval 60` in client `config` |

---

## 3. Laptop Power Tuning: TLP Configuration

If the host runs `tlp` for laptop power optimization, TLP may disconnect Wi-Fi or enforce PCIe Active State Power Management (ASPM) during battery/AC transitions:

```bash
# Check if TLP is active
systemctl is-active tlp 2>/dev/null

# Edit /etc/tlp.conf to preserve network performance
# Ensure the following parameters are set:
# WIFI_PWR_ON_AC=off
# WIFI_PWR_ON_BAT=off
# PCIE_ASPM_ON_AC=default
```

After modifying `/etc/tlp.conf`, apply changes:
```bash
sudo tlp start
```

---

## 4. Client-Side Quick Fixes (PowerShell & Bash)

If you do not have administrative access to change `/etc/sshd_config` on the remote server, enforce keepalives directly from your client connection command:

### Linux / macOS Terminal:
```bash
ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes '<USER>'@'<TARGET_HOST>'
```

### Windows PowerShell:
```powershell
ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes "<USER>@<TARGET_HOST>"
```
