---
title: Administration — Email Authentication Deployment (SPF, DKIM & DMARC)
type: workflow
platforms:
  - Linux
  - Microsoft 365
languages:
  - Bash
  - PowerShell
tasks:
  - Administration
  - Hardening
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - email
  - spf
  - dkim
  - dmarc
  - anti-spoofing
  - dns
  - hardening
---

# Administration — Email Authentication Deployment (SPF, DKIM & DMARC)

Production implementation runbook for eliminating domain impersonation and phishing risks using the email authentication triad: Sender Policy Framework (SPF), DomainKeys Identified Mail (DKIM), and Domain-based Message Authentication, Reporting, and Conformance (DMARC).

---

## 1. Step 1: SPF Record Synthesis & Flattening

Sender Policy Framework (RFC 7208) authorizes IP addresses and mail servers permitted to send email on behalf of your domain.

### The 10-DNS-Lookup Limit Constraint
RFC 7208 mandates that SPF evaluations must not exceed **10 DNS lookups** (triggered by `include`, `a`, `mx`, `ptr`, and `redirect` mechanisms). Exceeding 10 lookups causes recipient MTAs to return a `PermError`, discarding your SPF protection.

### Production SPF Record Structure
```text
v=spf1 ip4:<OUTBOUND_IP_CIDR> include:spf.protection.outlook.com ~all
```

- `ip4:<OUTBOUND_IP_CIDR>`: Direct IP or CIDR block (costs 0 DNS lookups).
- `include:_spf.example.com`: Authorizes third-party SaaS senders (costs 1+ DNS lookups).
- `~all` (SoftFail): Marks unauthorized senders as suspicious but delivers to spam/quarantine during onboarding. Never use `-all` (HardFail) until DMARC alignment is verified.

### Validate Current SPF Lookups
```bash
# Query SPF record via DNS TXT lookup
dig +short TXT '<PRIMARY_DOMAIN>' | grep "v=spf1"
```
```powershell
# Windows: Retrieve and parse SPF TXT record
(Resolve-DnsName -Name '<PRIMARY_DOMAIN>' -Type TXT).Strings | Where-Object { $_ -match "v=spf1" }
```

---

## 2. Step 2: DKIM Key Generation & DNS Publishing

DomainKeys Identified Mail (RFC 6376) cryptographically signs outbound emails using an asymmetric private key. The recipient MTA verifies the signature using the public key published in DNS.

### Linux / OpenDKIM Key Generation
```bash
# Generate 2048-bit DKIM key pair with unique selector (e.g. 's1')
opendkim-genkey -b 2048 -d '<PRIMARY_DOMAIN>' -s '<SELECTOR>'

# Restrict private key permissions
chmod 600 '<SELECTOR>.private'

# Inspect public key record formatted for DNS TXT entry
cat '<SELECTOR>.txt'
```

### DNS Record Format for DKIM
Publish a DNS TXT record at `<SELECTOR>._domainkey.<PRIMARY_DOMAIN>`:

```text
# Host / Name:
<SELECTOR>._domainkey.<PRIMARY_DOMAIN>

# TXT Value:
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
```

### Microsoft 365 Exchange Online (PowerShell)
```powershell
# Connect to Exchange Online and enable DKIM signing
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

# Create DKIM signing keys and enable rotation
New-DkimSigningConfig -DomainName '<PRIMARY_DOMAIN>' -Enabled $true
Get-DkimSigningConfig -Identity '<PRIMARY_DOMAIN>' | Select-Object Domain, Enabled, Status
```

---

## 3. Step 3: Phased DMARC Policy Escalation Lifecycle

DMARC (RFC 7489) requires either SPF or DKIM to pass **and align** with the header `From:` address. Never deploy DMARC directly into `p=reject`. Execute this 4-phase rollout over 6 to 12 weeks:

```text
┌───────────────────────┐     ┌───────────────────────┐     ┌───────────────────────┐     ┌───────────────────────┐
│   PHASE 1: MONITOR    │ ──► │  PHASE 2: QUARANTINE  │ ──► │  PHASE 3: ESCALATED   │ ──► │    PHASE 4: REJECT    │
│  p=none (Audit Only)  │     │ p=quarantine (pct=25) │     │ p=quarantine (pct=100)│     │  p=reject (Enforced)  │
└───────────────────────┘     └───────────────────────┘     └───────────────────────┘     └───────────────────────┘
```

### Phase 1: Monitoring Mode (`p=none`)
Collect aggregate XML telemetry reports (`rua`) to identify all shadow IT, CRM, and third-party senders without impacting email deliverability:

```text
# DNS TXT at _dmarc.<PRIMARY_DOMAIN>
v=DMARC1; p=none; rua=mailto:dmarc-reports@<PRIMARY_DOMAIN>; ruf=mailto:dmarc-forensics@<PRIMARY_DOMAIN>; fo=1
```

- `rua=mailto:...`: Destination mailbox for daily aggregate XML performance summaries.
- `fo=1`: Generates forensic failure reports if *either* SPF or DKIM fails.

### Phase 2: Partial Quarantine (`p=quarantine; pct=25`)
Instruct recipient mail servers to route 25% of unaligned messages to the recipient's spam folder:

```text
v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@<PRIMARY_DOMAIN>; fo=1
```

### Phase 3: Full Quarantine (`p=quarantine; pct=100`)
Enforce quarantine across 100% of unaligned messages:

```text
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@<PRIMARY_DOMAIN>; fo=1
```

### Phase 4: Strict Enforcement & Reject (`p=reject`)
Permanently block and discard unauthorized emails at the MTA boundary:

```text
v=DMARC1; p=reject; rua=mailto:dmarc-reports@<PRIMARY_DOMAIN>; fo=1
```

---

## 4. Live Verification & Header Inspection

### Query DNS Records Remotely
```bash
# 1. Query DMARC policy record
dig +short TXT '_dmarc.<PRIMARY_DOMAIN>'

# 2. Query DKIM public key
dig +short TXT '<SELECTOR>._domainkey.<PRIMARY_DOMAIN>'
```

### Inspect Raw Inbound Email Authentication Headers
Send a test email to an external account (e.g., Gmail, Outlook) and inspect the `Authentication-Results` header in the raw email source:

```text
Authentication-Results: mx.google.com;
       dkim=pass header.i=@<PRIMARY_DOMAIN> header.s=<SELECTOR> header.b=XyZ...;
       spf=pass (google.com: domain of sender@<PRIMARY_DOMAIN> designates 198.51.100.10 as permitted sender) smtp.mailfrom=sender@<PRIMARY_DOMAIN>;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=<PRIMARY_DOMAIN>
```

---

## Related Guides

- [Fundamentals — SMTP Protocol, Relays & Email Authentication](../../fundamentals/networking/smtp.md)
- [Tasks — Phishing Email Triage & Header Analysis](../incident-response/phishing-email-triage.md)
- [Microsoft 365 Exchange Online Hardening](../../platforms/microsoft-365/exchange.md)
- [DNS Client Resolution and Troubleshooting](dns-resolution-troubleshooting.md)
