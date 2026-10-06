---
title: Administration — Group Policy Force Refresh & Diagnostic Audit
type: workflow
platforms:
  - Windows
  - Active Directory
languages:
  - PowerShell
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - administration
  - group-policy
  - gpo
  - gpupdate
---

# Administration — Group Policy Force Refresh & Diagnostic Audit

Procedures to remotely trigger Group Policy updates and audit applied GPO results (`gpresult`).

## 1. Remote GPO Force Refresh

```powershell
param([string]$ComputerName)

# Initiates background GPO update via PowerShell remoting
Invoke-GPUpdate -Computer $ComputerName -Force -RandomDelayInMinutes 0
```

## 2. Generate HTML Diagnostic Report

```powershell
# Generate full applied GPO audit report
gpresult /h C:\Temp\gpreport.html
```
