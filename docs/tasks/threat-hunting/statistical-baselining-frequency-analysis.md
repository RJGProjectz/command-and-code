---
title: Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)
type: workflow
platforms:
  - Windows
  - Linux
  - Microsoft Defender
  - Splunk
  - SentinelOne
languages:
  - KQL
  - SPL
  - S1QL
  - PowerShell
  - Bash
tasks:
  - Threat Hunting
  - Detection Engineering
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - threat-hunting
  - statistical-baselining
  - lfo
  - frequency-analysis
  - beaconing
  - jitter
  - process-anomalies
---

# Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)

Adversaries often blend into enterprise environments by living off the land or utilizing common protocols. While individual commands may appear legitimate in isolation, **Least Frequency of Occurrence (LFO)** and statistical variance analysis isolate stealthy behaviors by surfacing anomalous outliers that execute on less than $1\%$ of the fleet.

---

## 1. Principles of Least Frequency of Occurrence (LFO)

In an enterprise fleet of thousands of endpoints, standard administrative and user behaviors cluster tightly around predictable frequencies. Malicious tools, staged backdoors, and targeted living-off-the-land commands typically exhibit long-tail distribution curves.

```
Frequency
▲
│ ██████████ (Standard IT Tools / Updaters / System Apps: 10,000+ executions)
│ █████ (Common User Apps: 2,000+ executions)
│ █ (Approved Admin Scripts: 100+ executions)
│ ▏ ▏ ▏ ▏  ◄─── TARGET HUNT ZONE: Long-Tail Outliers (1-3 endpoints only)
└────────────────────────────────────────────────────────────────────────► Unique Signatures
```

### Analysis Best Practices
* **Cluster by Parent-Child Hierarchy:** Never analyze process names in isolation; evaluate `(ParentProcess, ChildProcess, ProcessCommandLine)`.
* **Strip Dynamic Tokens:** Normalize command lines by removing dynamic session GUIDs, PIDs, and timestamp arguments before computing hashes or counts.
* **Filter Fleet-Wide Uniformity:** Filter out signatures present on $\ge 90\%$ of endpoints to eliminate core operating system noise.

---

## 2. Hunt 1: Parent-Child Process Anomaly Baselining

Standard Windows operating system processes have strict, predictable parentage. For example, `svchost.exe` should be spawned exclusively by `services.exe`, and web servers like `w3wp.exe` or `httpd` should rarely spawn interactive shells or scripting interpreters.

### Microsoft Defender XDR (KQL): Rare Children of Common Parent Binaries

```kql
// Identify rare child processes spawned by explorer.exe or svchost.exe across the fleet
let Timeframe = 14d;
let TargetParents = dynamic(["svchost.exe", "explorer.exe", "w3wp.exe", "wmiprvse.exe"]);
DeviceProcessEvents
| where TimeGenerated >= ago(Timeframe)
| where InitiatingProcessFileName in~ (TargetParents)
| project DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| summarize 
    HostCount = dcount(DeviceName),
    ExecutionCount = count(),
    SampleHosts = make_set(DeviceName, 5),
    SampleCommands = make_set(ProcessCommandLine, 3)
    by InitiatingProcessFileName, FileName
// Long-tail filter: Binaries executed on 3 or fewer hosts across the entire organization
| where HostCount <= 3
| sort by HostCount asc, ExecutionCount asc
```

### Splunk (SPL): Rare Web Server Child Processes (Web Shell Hunting)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    [ search index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe")
    | table Image, ParentImage ]
| stats count as ExecCount, dc(Computer) as HostCount, values(Computer) as SampleHosts, values(CommandLine) as Commands by ParentImage, Image
| where HostCount < 3
| sort + HostCount, + ExecCount
```

### SentinelOne (S1QL): Rare System Service Children

```sql
EventType = "Process Creation" 
AND EndpointOS = "windows" 
AND ParentProcessName in ("svchost.exe", "services.exe", "lsass.exe")
| group HostCount = count_distinct(EndpointName), ExecCount = count() by ParentProcessName, ProcessName
| filter HostCount <= 2
| order by HostCount asc
```

---

## 3. Hunt 2: Network C2 Beaconing & Jitter Calculation

Command and Control (C2) frameworks (e.g., Cobalt Strike, Mythic, Sliver) communicate with external listener infrastructure at periodic intervals. Even when operators configure **sleep jitter** (e.g., $30\text{s} \pm 20\%$), the statistical delta between connection times creates a distinct distribution compared to human browsing or standard cloud sync traffic.

### Mathematical Formulation of Beaconing Jitter

Let $t_1, t_2, \dots, t_n$ be the sequence of connection timestamps from a host to an external IP.
The inter-arrival delta is $\Delta t_i = t_{i} - t_{i-1}$.

$$\text{Mean Interval } (\mu) = \frac{1}{n-1} \sum_{i=2}^n \Delta t_i$$

$$\text{Standard Deviation } (\sigma) = \sqrt{\frac{1}{n-1} \sum_{i=2}^n (\Delta t_i - \mu)^2}$$

$$\text{Jitter Coefficient } (CV) = \frac{\sigma}{\mu}$$

* **Automated C2 Beacon Profile:** $0.05 \le CV \le 0.40$ (tight distribution with deliberate jitter).
* **Scheduled NTP / Sync:** $CV < 0.02$ (exact rigid interval).
* **Human Web Browsing:** $CV > 1.20$ (random bursts).

### Microsoft Defender XDR (KQL): Outbound Connection Inter-Arrival Variance

```kql
// Calculate connection intervals and delta variance for outbound connections
let StartTime = ago(7d);
DeviceNetworkEvents
| where TimeGenerated >= StartTime
| where ActionType == "ConnectionSuccess"
// Focus on non-standard web ports or external IPs
| where RemoteIPType == "Public" and RemotePort !in (80, 443, 53)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| sort by DeviceName asc, RemoteIP asc, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1),
         PrevDevice = prev(DeviceName, 1),
         PrevIP = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevIP
| extend TimeDeltaSec = datetime_diff('second', TimeGenerated, PrevTime)
| where TimeDeltaSec between (5 .. 3600)
| summarize 
    ConnectionCount = count(),
    AvgDeltaSec = avg(TimeDeltaSec),
    StdDevDeltaSec = stdev(TimeDeltaSec),
    MinDelta = min(TimeDeltaSec),
    MaxDelta = max(TimeDeltaSec)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
// Filter for recurring sessions with low variance (beaconing profile)
| where ConnectionCount >= 20
| extend JitterRatio = round(StdDevDeltaSec / AvgDeltaSec, 3)
| where JitterRatio between (0.05 .. 0.45)
| sort by ConnectionCount desc, JitterRatio asc
```

### Splunk (SPL): Outbound Streamstats Beaconing Analysis

```spl
index=network sourcetype="pan:traffic" action=allowed dest_ip!="10.0.0.0/8" dest_ip!="172.16.0.0/12" dest_ip!="192.168.0.0/16"
| sort 0 src_ip, dest_ip, _time
| streamstats current=f window=1 last(_time) as prev_time by src_ip, dest_ip
| eval delta_sec = _time - prev_time
| where delta_sec > 10 AND delta_sec < 1800
| stats count as connection_count, avg(delta_sec) as avg_interval, stdev(delta_sec) as std_interval by src_ip, dest_ip, dest_port
| where connection_count >= 15
| eval jitter = round(std_interval / avg_interval, 3)
| where jitter >= 0.05 AND jitter <= 0.40
| sort - connection_count, + jitter
```

---

## 4. Hunt 3: Rare Fleet-Wide Service Registrations

Adversaries establish persistence or execute remote lateral movement payloads (e.g., PsExec, Impacket `smbexec`) by registering new Windows services or deploying novel Linux `systemd` units.

### Windows Service Installation Baselining (Event ID 7045)

```kql
// Identify rare newly installed Windows services across enterprise endpoints
SecurityEvent
| where EventID == 7045
| extend ServiceName = extract(@"Service Name:\s+([^\r\n]+)", 1, EventData),
         ImagePath = extract(@"Service File Name:\s+([^\r\n]+)", 1, EventData),
         ServiceType = extract(@"Service Type:\s+([^\r\n]+)", 1, EventData),
         Account = extract(@"Service Account:\s+([^\r\n]+)", 1, EventData)
| summarize 
    HostCount = dcount(Computer),
    InstallCount = count(),
    SampleHosts = make_set(Computer, 3),
    SampleAccounts = make_set(Account, 2)
    by ServiceName, ImagePath
// Isolate services registered on fewer than 3 machines
| where HostCount <= 2
| sort by HostCount asc, InstallCount asc
```

### Linux Fleet Rare Systemd Unit Audit

```bash
# Execute across Linux fleet via orchestration to identify rare custom services
find /etc/systemd/system /usr/lib/systemd/system -type f -name "*.service" -not -path "*/multi-user.target.wants/*" -exec md5sum {} + | sort | uniq -w32 -c | sort -n | head -n 20
```

---

## 5. Hunt 4: Fleet-Wide Rare Scheduled Tasks

Adversaries frequently abuse scheduled tasks to bypass reboot persistence barriers. While enterprise software deployers create standard scheduled tasks across all systems, custom lateral movement or backdoor persistence tasks are isolated to single targets.

### Splunk (SPL): Long-Tail Windows Scheduled Task Creation (Event ID 4698)

```spl
index=wineventlog EventCode=4698
| spath input=Message output=TaskName path=TaskName
| spath input=Message output=Command path=Actions.Exec.Command
| spath input=Message output=Arguments path=Actions.Exec.Arguments
| eval TaskDefinition = Command . " " . coalesce(Arguments, "")
| stats count as TotalInstalls, dc(Computer) as HostCount, values(Computer) as TargetHosts by TaskName, TaskDefinition
| where HostCount <= 2
| sort + HostCount, + TotalInstalls
```

### Microsoft Defender XDR (KQL): Schtasks / Cron Command Line Baselining

```kql
DeviceProcessEvents
| where FileName in~ ("schtasks.exe", "crontab", "at.exe")
| where ProcessCommandLine has_any ("/create", "/change", "-e", "install")
| summarize 
    HostCount = dcount(DeviceName), 
    RunCount = count(), 
    Hosts = make_set(DeviceName, 3), 
    Commands = make_set(ProcessCommandLine, 3) 
    by ProcessCommandLine
| where HostCount <= 2
| sort by HostCount asc
```

---

## 6. False Positive Suppression & Baseline Maintenance

When tuning statistical baselines:
1. **Exclude Known Deployment Orchestrators:** If SCCM (`CcmExec.exe`), Tanium, or Ansible executes scheduled tasks or services, explicitly filter the initiating parent process identity rather than disabling the query logic.
2. **Standardize Path Casing:** Always use case-insensitive string operators (`in~`, `=~`, `has_any`) when evaluating file paths and usernames to prevent artificial fragmentation.
3. **Persist Validated Hashes:** Export validated administrative tool hashes into an offline lookup list (`known_fleet_admin_hashes.csv`) to suppress recurring noise.
