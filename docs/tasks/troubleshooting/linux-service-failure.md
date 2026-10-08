---
title: Linux Service Failure Troubleshooting
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Troubleshooting, Administration]
category: Workflow
tags: [workflow, troubleshooting, systemd, journalctl, service failed]
aliases: [service failed to start, systemd unit failed, service keeps restarting, troubleshoot linux service]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Service Failure Troubleshooting

**Symptom:** a systemd service fails to start, stops unexpectedly, or restarts in a loop.

<div class="cc-tree" data-title="Linux Service Diagnostic Flow" markdown>

<div class="cc-node cc-node--root" data-id="step-status" markdown>

#### Step 1: Unit Status and State Inspection

Check the current systemd unit active state, exit code, and recent runtime log:

```bash
systemctl status '<SERVICE_NAME>' --no-pager -l
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-exit-code">✗ Active: failed (Exit Code)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-crash-loop">⏳ Activating (auto-restart) / Crash Loop</button>
<button type="button" class="cc-branch-btn" data-next="step-inactive">? Inactive (dead) / Masked</button>
</div>

</div>

<div class="cc-node" data-id="step-exit-code" markdown>

#### Step 2: Journal Log and Exit Code Diagnostics

Extract the last 50 journal entries for the service to identify the exact runtime exception:

```bash
journalctl -u '<SERVICE_NAME>' -b --no-pager | tail -50
```

**What error appears in the journal log?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-perm-denied">Permission Denied / status=203</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-port-conflict">Address already in use / status=98</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-oom-kill">Killed / status=137 (OOM)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-perm-denied" markdown>

#### Diagnostic Branch: Permissions & Security Context

`Permission denied` or `status=203/EXEC` indicates file ownership, execution bit, or Mandatory Access Control denials:

```bash
# 1. Inspect unit file execution command and service user
systemctl cat '<SERVICE_NAME>' | grep -E "User|Group|ExecStart"

# 2. Verify binary permissions and execute manually as service user
sudo -u '<SERVICE_USER>' /path/to/binary --config /etc/service.conf

# 3. Check for SELinux / AppArmor audit denials
sudo ausearch -m avc -ts recent
sudo dmesg | grep -i apparmor
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-port-conflict" markdown>

#### Diagnostic Branch: Port Binding Conflict

`Address already in use` means another process has bound to the listening IP/port:

```bash
# 1. Identify conflicting process holding target listening port
sudo ss -tulpn | grep ':<PORT>'

# 2. Or query via lsof
sudo lsof -i ':<PORT>'
```

Terminate or reconfigure the conflicting daemon, then restart:
```bash
sudo systemctl restart '<SERVICE_NAME>'
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-oom-kill" markdown>

#### Diagnostic Branch: Out of Memory (OOM Killer)

Exit status 137 indicates the Linux kernel memory manager sent `SIGKILL` due to memory exhaustion:

```bash
# 1. Check kernel ring buffer for Out of Memory invocations
sudo dmesg -T | grep -i -E "oom|killed process"

# 2. Check system memory and swap utilization
free -h
```

Increase system memory, tune unit memory limits (`MemoryMax=`), or adjust application heap allocation.

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-crash-loop" markdown>

#### Diagnostic Branch: Crash Loop & Restart Throttling

When systemd reports `start request repeated too quickly`, reset the failure counters after fixing configuration:

```bash
# 1. Validate application configuration syntax before starting
# Examples: nginx -t, sshd -t, apachectl configtest, named-checkconf

# 2. Reset systemd unit failure count
sudo systemctl reset-failed '<SERVICE_NAME>'

# 3. Restart service cleanly
sudo systemctl restart '<SERVICE_NAME>'
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-inactive" markdown>

#### Diagnostic Branch: Service Inactive, Disabled or Masked

If a critical service is unexpectedly masked or disabled, check for administrative or adversary tampering:

```bash
# 1. Check if unit is masked (symlinked to /dev/null)
systemctl is-enabled '<SERVICE_NAME>'

# 2. Unmask and enable if legitimate
sudo systemctl unmask '<SERVICE_NAME>'
sudo systemctl enable --now '<SERVICE_NAME>'

# 3. Audit recent shell commands that disabled the service
sudo grep -E "systemctl (stop|disable|mask)" /root/.bash_history /home/*/.bash_history 2>/dev/null
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

</div>

---

## Detailed Step Reference

### 1. Status and recent logs

```bash
systemctl status '<SERVICE_NAME>' --no-pager -l
journalctl -u '<SERVICE_NAME>' -b --no-pager | tail -50
```

The status output shows the exit code and the last log lines. → [systemd](../../platforms/linux/systemd.md#inspect-a-service)

## 2. What exactly is it running?

```bash
systemctl cat SERVICE
```

Run the `ExecStart` command manually as the service's `User=` to see the real error:

```bash
sudo -u SERVICE_USER /path/to/binary --args
```

## 3. Common causes

| Symptom in logs | Check |
| --- | --- |
| `Permission denied` | file ownership/modes, SELinux/AppArmor denials → [troubleshooting](../../platforms/linux/troubleshooting.md#selinux-and-apparmor-denials) |
| `Address already in use` | another process holds the port → [process for a port](../../platforms/linux/networking.md#find-the-process-for-a-port) |
| `No space left on device` | disk or inodes → [disk full](../../platforms/linux/troubleshooting.md#disk-full) |
| `status=137` / killed | OOM killer → [OOM kills](../../platforms/linux/troubleshooting.md#out-of-memory-kills) |
| `start request repeated too quickly` | crash loop — fix the underlying error, then `systemctl reset-failed SERVICE` |

## 4. Config changes

Validate config before restarting (examples: `nginx -t`, `sshd -t`, `apachectl configtest`, `named-checkconf`). After editing unit files: `systemctl daemon-reload`.

## 5. Security angle

An unexpected failure of a security service (auditd, EDR agent, syslog forwarder) can be tampering. Check who changed it:

```bash
sudo find /etc/systemd /usr/lib/systemd -name 'SERVICE*' -newer /etc/hostname -ls
sudo grep -E 'systemctl (stop|disable|mask)' /root/.bash_history /home/*/.bash_history 2>/dev/null
```
