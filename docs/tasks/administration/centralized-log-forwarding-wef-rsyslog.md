---
title: Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)
type: workflow
platforms:
  - Windows Server
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Administration
  - Hardening
  - Assurance
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - wef
  - event-forwarding
  - rsyslog
  - logging
  - telemetry
  - auditd
  - hardening
---

# Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)

Production runbook for establishing an agentless, centralized enterprise log forwarding pipeline using native Windows Event Forwarding (WEF) over WinRM and hardened Linux Rsyslog TLS forwarding with RELP and kernel auditd plugins.

---

## 1. Pipeline Architecture

A resilient log pipeline eliminates heavy third-party endpoint agents by utilizing native operating system transport protocols:

```text
[ Windows Endpoints ] ──(WinRM HTTP:5985 / Kerberos)──► [ Windows Event Collector (WEC) ] ──► [ SIEM / Concentrator ]
                                                                                                      ▲
[ Linux Endpoints   ] ──(Rsyslog TLS:6514 / RELP)─────────────────────────────────────────────────────┘
```

- **Windows**: Source-initiated WEF pushes events from endpoints to a central Windows Event Collector (WEC) over native WinRM with Kerberos encryption.
- **Linux**: Rsyslog forwards system and kernel audit logs over TLS-encrypted TCP port 6514 with disk-assisted queuing to prevent log loss during network partitions.

---

## 2. Windows Event Forwarding (WEF) Enterprise Rollout

In source-initiated subscriptions, domain computers connect outbound to the collector. This eliminates inbound firewall openings on client endpoints.

### Step 1: Configure the Windows Event Collector (WEC)
Run in an elevated PowerShell session on the dedicated Collector server:

```powershell
# 1. Initialize and configure Windows Event Collector service
wecutil.exe qc /q

# 2. Configure WinRM service to accept incoming subscription queries
winrm.cmd quickconfig -q

# 3. Ensure WinRM service starts automatically
Set-Service -Name "WinRM" -StartupType Automatic
Set-Service -Name "WecSvc" -StartupType Automatic
```

### Step 2: Configure Client Endpoints via Group Policy
Deploy these settings to domain computers via Active Directory GPO:

1. **Enable WinRM Service**: Set `Windows Remote Management (WS-Management)` service to **Automatic**.
2. **Grant Event Log Read Permissions**: Add the `Network Service` account to the built-in **Event Log Readers** local security group (required for WinRM to read Security and Sysmon logs):
   ```powershell
   # PowerShell local test command
   Add-LocalGroupMember -Group "Event Log Readers" -Member "NT AUTHORITY\Network Service"
   ```
3. **Configure Subscription Manager GPO**:
   - Path: `Computer Configuration > Policies > Administrative Templates > Windows Components > Event Forwarding`:
   - Setting: **Configure target Subscription Manager** $\rightarrow$ **Enabled**.
   - Value:
     ```text
     Server=http://<COLLECTOR_FQDN>:5985/wsman/SubscriptionManager/WEC,Refresh=60
     ```

### Step 3: Create Source-Initiated Subscription (`baseline_subscription.xml`)
On the Collector server, define the events to collect (Sysmon, Security, PowerShell Script Block):

```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>Enterprise-Security-Baseline</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Forwards Sysmon, Security, and ScriptBlock logs</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>MinLatency</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>100</MaxItems>
      <MaxLatencyTime>15000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="1800000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0">
          <!-- Security: Process Create (4688), User Added (4720), Service Installed (7045) -->
          <Select Path="Security">*[System[(EventID=4688 or EventID=4720 or EventID=4738 or EventID=7045)]]</Select>
          <!-- PowerShell Script Block Logging -->
          <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select>
          <!-- All Sysmon Events -->
          <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>http</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)S:</AllowedSourceDomainComputers>
</Subscription>
```

```powershell
# Create subscription from XML file
wecutil.exe cs "baseline_subscription.xml"

# Check subscription status and active connected endpoints
wecutil.exe gr "Enterprise-Security-Baseline"
```

---

## 3. Linux Rsyslog Encrypted TLS Forwarding with RELP

Standard UDP 514 syslog is unencrypted and silently drops packets under congestion. Rsyslog with TLS and RELP (Reliable Event Logging Protocol) guarantees delivery with cryptographic privacy.

### Install Packages
```bash
sudo apt-get update && sudo apt-get install -y rsyslog rsyslog-gnutls rsyslog-relp
```

### Configure Secure Forwarding (`/etc/rsyslog.d/50-remote-tls.conf`)
Configure TLS network stream drivers and disk-assisted memory queues:

```text
# Certificate authority and client credentials
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca-bundle.crt"
    DefaultNetstreamDriverCertFile="/etc/ssl/certs/client.crt"
    DefaultNetstreamDriverKeyFile="/etc/ssl/private/client.key"
)

# Forward all logs to remote SIEM / concentrator over TLS with disk queueing
action(
    type="omfwd"
    target="<SIEM_COLLECTOR_IP>"
    port="6514"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="anon"
    queue.type="LinkedList"
    queue.filename="fwdRuleQueue"
    queue.maxdiskspace="1g"
    queue.saveonshutdown="on"
    action.resumeRetryCount="-1"
)
```

```bash
# Validate Rsyslog configuration syntax and restart service
sudo rsyslogd -N1 && sudo systemctl restart rsyslog
```

---

## 4. Bridge Linux Kernel Auditd into Rsyslog (`audisp-syslog`)

The Linux kernel `auditd` subsystem records syscalls, privilege escalation, and file modifications. Forward these events through the Rsyslog TLS pipeline:

```bash
# Enable audit dispatcher syslog plugin
sudo sed -i 's/^active = no/active = yes/' /etc/audit/plugins.d/syslog.conf

# Restart auditd daemon to activate plugin
sudo systemctl restart auditd || sudo service auditd restart
```

---

## 5. Verification & Telemetry Testing

### Verify Windows Forwarded Events
On the WEC server, verify incoming events inside the `ForwardedEvents` channel:

```powershell
# Query last 10 forwarded events on WEC server
Get-WinEvent -LogName "ForwardedEvents" -MaxEvents 10 | Select-Object TimeCreated, Id, ProviderName, MachineName
```

### Verify Linux Remote Forwarding
```bash
# Send test authentication notice to local syslog
logger -p auth.notice "WEF_RSYSLOG_TEST: Verification log entry from $(hostname)"
```

---

## Related Guides

- [Administration — Sysmon Enterprise Deployment & Telemetry Tuning](sysmon-deployment-tuning.md)
- [Linux Logs Reference](../../platforms/linux/logs.md)
- [Windows Event Logs Reference](../../platforms/windows/event-logs.md)
- [Splunk REST API Management](../../apis/splunk/management-jobs.md)
