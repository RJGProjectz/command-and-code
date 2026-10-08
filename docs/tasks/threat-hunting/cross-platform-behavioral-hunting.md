---
title: Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
  - Microsoft Defender
  - Splunk
  - SentinelOne
languages:
  - PowerShell
  - Bash
  - KQL
  - SPL
  - S1QL
tasks:
  - Threat Hunting
  - Detection Engineering
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - threat-hunting
  - cross-platform
  - memory-injection
  - credential-access
  - anti-forensics
  - auditd
  - sysmon
---

# Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)

Enterprise intrusions frequently pivot across heterogeneous operating systems. While initial access may target Windows workstations, lateral movement and staging often transition to Linux infrastructure. This guide aligns behavioral telemetry archetypes across Windows (Security Event Log, Sysmon, MDE) and Linux (Auditd, Syslog, eBPF, MDE for Linux).

---

## 1. Unified Cross-Platform Behavioral Architecture

| Adversary TTP | Windows Telemetry Primitive | Linux Telemetry Primitive | Key Behavioral Signature |
| :--- | :--- | :--- | :--- |
| **In-Memory Injection** | Sysmon Event ID 8, 10, 25; MDE `DeviceEvents` | Auditd `ptrace`, `mmap(PROT_EXEC)`, `/proc/$PID/mem` | Cross-process memory writes, unbacked executable memory |
| **Credential Access** | Sysmon Event ID 10 (`lsass.exe`), Event ID 4624 | Auditd open `/etc/shadow`, read `/tmp/krb5cc_*` | Non-system processes accessing security credential stores |
| **Defense Evasion** | Event ID 1102, `wevtutil.exe cl`, mini-filter tampering | `auditctl -e 0`, `/dev/null` log redirect, `HISTFILE` tampering | Abrupt stoppage or truncation of security logging subsystems |
| **Fileless Execution** | LOLBAS unmanaged PowerShell / C# execution | `memfd_create()`, `perl`/`python` direct RAM execution | Binary execution without corresponding disk writes |

---

## 2. Behavioral Hunt 1: In-Memory Code Injection & Evasion

### Windows Endpoint Telemetry: Thread Injection & Process Hollowing

Adversaries inject shellcode into legitimate processes (e.g., `explorer.exe`, `svchost.exe`, `notepad.exe`) to mask network connections and bypass file-based scanner telemetry.

#### Microsoft Defender XDR (KQL): Process Access & Thread Injection

```kql
// Detect suspicious thread injection or memory modification into sensitive targets
DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall", "OpenProcessApiCall")
| extend DesiredAccess = tostring(AdditionalFields.DesiredAccess)
// Check for PROCESS_ALL_ACCESS (0x1F0FFF) or PROCESS_VM_WRITE | PROCESS_VM_OPERATION (0x0028 / 0x1000)
| where DesiredAccess has_any ("0x1F0FFF", "0x0028", "0x1428", "0x1fffff")
| where InitiatingProcessFileName !in~ ("csrss.exe", "lsass.exe", "svchost.exe", "MsMpEng.exe")
| where FileName in~ ("explorer.exe", "svchost.exe", "spoolsv.exe", "rundll32.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, DesiredAccess
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count() 
    by DeviceName, InitiatingProcessFileName, FileName, DesiredAccess
```

#### SentinelOne (S1QL): Cross-Process Injection

```sql
EventType = "Remote Thread" 
AND EndpointOS = "windows" 
AND TargetProcessName in ("explorer.exe", "svchost.exe", "dllhost.exe")
AND NOT SourceProcessName in ("MsMpEng.exe", "csrss.exe", "services.exe")
| group EventCount = count() by EndpointName, SourceProcessName, TargetProcessName
| order by EventCount desc
```

### Linux Endpoint Telemetry: PTRACE & Memory-Only `memfd_create`

On Linux, adversaries utilize `ptrace(PTRACE_POKETEXT)` to inject code into running processes or abuse `memfd_create()` to run ELF binaries purely from RAM without writing to disk.

#### Linux Auditd Hunt: Anomalous `ptrace` Syscalls

```spl
index=linux sourcetype="auditd" syscall=101 OR syscall=26
| eval syscall_name = case(syscall==101, "ptrace", syscall==26, "ptrace_compat", true(), "other")
| where comm!="gdb" AND comm!="strace" AND comm!="lldb"
| stats count, values(exe) as CallingBinaries, values(comm) as Commands by host, uid, syscall_name
| where count < 5
```

#### Linux Bash Command: Audit Memory Execution (`/proc`)

```bash
# Detect processes running from deleted files or memory-only memfd mounts
ls -l /proc/*/exe 2>/dev/null | grep -E '\(deleted\)|memfd:' | awk '{print $NF, $0}'
```

---

## 3. Behavioral Hunt 2: Credential & Secret Access

### Windows: LSASS Memory Dumping Patterns

Adversaries harvest credentials using tools like Mimikatz or built-in utilities (`procdump.exe`, `comsvcs.dll`, Task Manager).

#### Splunk (SPL): LSASS Memory Read Access (Sysmon Event ID 10)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
    TargetImage="*\\lsass.exe"
| eval GrantedAccess = upper(GrantedAccess)
| where GrantedAccess="0x1010" OR GrantedAccess="0x1F0FFF" OR GrantedAccess="0x1410" OR GrantedAccess="0x1FFFFF"
| search NOT (SourceImage="*\\MsMpEng.exe" OR SourceImage="*\\svchost.exe" OR SourceImage="*\\csrss.exe")
| stats count, earliest(_time) as FirstSeen, latest(_time) as LastSeen by Computer, SourceImage, GrantedAccess, CallTrace
| sort - count
```

### Linux: Unauthorized Shadow & Kerberos Ticket File Access

On Linux, adversary credential access targets `/etc/shadow`, GSSAPI/Kerberos credential caches (`/tmp/krb5cc_*`), or PAM configuration files.

#### Splunk (SPL): Sensitive Credential File Access via Auditd

```spl
index=linux sourcetype="auditd" type="PATH" (name="/etc/shadow" OR name="/etc/gshadow" OR name="/tmp/krb5cc_*")
| search NOT (ouid=0 AND (comm="passwd" OR comm="sudo" OR comm="login" OR comm="sshd" OR comm="cron"))
| stats count, values(comm) as Processes, values(name) as Targets by host, uid, exe
| sort - count
```

#### Linux Live Verification: Auditd Rule Configuration

```bash
# Verify auditd rules monitoring credential stores
auditctl -l | grep -E "shadow|krb5"

# Expected baseline configuration:
# -w /etc/shadow -p rwa -k shadow_access
# -w /etc/gshadow -p rwa -k gshadow_access
```

---

## 4. Behavioral Hunt 3: Anti-Forensics & Log Tampering

Adversaries attempt to blind security teams by terminating log forwarders, clearing system event logs, or setting environment variables that disable shell history.

### Windows: Security Log Clear & Service Disruption

* **Security Event ID 1102:** "The audit log was cleared."
* **System Event ID 104:** "The System log file was cleared."
* **Service Control Manager (Event ID 7036):** Windows Event Log service stopped.

#### Microsoft Defender XDR (KQL): Event Clearing & Disruption

```kql
// Detect event clearing commands or audit log reset events
let ClearedEvents = SecurityEvent
| where EventID in (1102, 104)
| project TimeGenerated, DeviceName = Computer, EventID, Activity = "Audit Log Cleared", Account;
let CliClearing = DeviceProcessEvents
| where FileName in~ ("wevtutil.exe", "powershell.exe")
| where ProcessCommandLine has_any (" cl ", "clear-log", "Clear-EventLog", "wevtutil.exe cl")
| project TimeGenerated, DeviceName, EventID = 4688, Activity = ProcessCommandLine, Account = AccountName;
union ClearedEvents, CliClearing
| sort by TimeGenerated desc
```

### Linux: Shell History Evasion & Audit Subsystem Disabling

Adversaries execute `export HISTFILE=/dev/null`, `unset HISTFILE`, `set +o history`, or run `auditctl -e 0` to disable the Linux audit framework.

#### Linux Bash & Auditd Detection

```bash
# Inspect active user sessions for suppressed history configurations
for pid in $(pgrep -f "bash|zsh|sh"); do
    environ_file="/proc/$pid/environ"
    if [ -f "$environ_file" ]; then
        if tr '\0' '\n' < "$environ_file" | grep -E '^HISTFILE=/dev/null|^HISTSIZE=0'; then
            echo "[ALERT] Tampered history environment detected on PID: $pid"
        fi
    fi
done
```

#### Splunk (SPL): Linux Audit Subsystem Disabled

```spl
index=linux sourcetype="auditd" type="CONFIG_CHANGE"
| where audit_enabled=0 OR op="temporarily_disable"
| stats count, earliest(_time) as FirstSeen by host, auid, comm, exe
```

---

## 5. Unified Cross-Platform Hunt Runbook

When hunting across enterprise enclaves:

1. **Simultaneous Triage:** If a host is identified as compromised, immediately sweep the paired infrastructure (e.g., if Windows jump-box shows anomalous activity, query SSH logins from that jump-box to Linux bastions).
2. **Correlate Kerberos & SSH Keys:** Pivot from Kerberos ticket issuances (Event ID 4768 / 4769) to Linux PAM Kerberos authentication events (`pam_krb5`).
3. **Compare Persistence Mechanisms:** On Windows, inspect Scheduled Tasks (`schtasks`) and Registry Run keys; on Linux, inspect `/etc/cron*`, `/etc/systemd/system/`, and user `crontab` files.
