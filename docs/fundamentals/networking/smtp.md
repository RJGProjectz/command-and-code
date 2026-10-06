---
title: Fundamentals — SMTP Protocol, Relays & Email Authentication
type: entry
platforms:
  - Linux
  - Microsoft 365
languages:
  - PowerShell
  - Bash
tasks:
  - Investigation
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - smtp
  - email
  - spf
  - dkim
  - dmarc
---

# Fundamentals — SMTP Protocol, Relays & Email Authentication

Simple Mail Transfer Protocol (SMTP) governs message transmission across TCP ports 25 (relay), 587 (client submission with STARTTLS), and 465 (SMTPS).

## 1. Transaction Handshake

```text
S: 220 mail.example.com ESMTP Postfix
C: EHLO client.network.local
S: 250-mail.example.com
S: 250-STARTTLS
S: 250 OK
C: MAIL FROM:<sender@example.com>
S: 250 2.1.0 Ok
C: RCPT TO:<recipient@target.com>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: Subject: Urgent Update
C: From: sender@example.com
C: Message payload here...
C: .
S: 250 2.0.0 Ok: queued as 4B7C91008
C: QUIT
S: 221 2.0.0 Bye
```

---

## 2. Anti-Spoofing Triple Crown: SPF, DKIM & DMARC

| Standard | Verification Method | DNS Record Type |
| :--- | :--- | :--- |
| **SPF** (Sender Policy Framework) | Validates sending server IP against authorized IP list | TXT (`v=spf1 ip4:198.51.100.0/24 include:_spf.google.com ~all`) |
| **DKIM** (DomainKeys Identified Mail) | Cryptographically signs message headers with private key; recipient verifies with public key | TXT (`selector._domainkey.example.com`) |
| **DMARC** | Dictates policy (`none`, `quarantine`, `reject`) if SPF or DKIM fail alignment | TXT (`_dmarc.example.com` `v=DMARC1; p=reject; rua=mailto:...`) |

---

## 3. Investigating Headers for Phishing

```powershell
# Query SPF and DMARC records via PowerShell
Resolve-DnsName -Name "example.com" -Type TXT | Where-Object Strings -match "v=spf1"
Resolve-DnsName -Name "_dmarc.example.com" -Type TXT
```
