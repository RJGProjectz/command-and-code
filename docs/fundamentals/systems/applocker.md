---
title: Fundamentals — AppLocker & Application Control Baselines
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - applocker
  - application-whitelisting
  - hardening
---

# Fundamentals — AppLocker & Application Control Baselines

AppLocker enforces application control rules in Windows, restricting software execution based on file path, hash, or publisher digital signatures.

## 1. Rule Collections

- **Executable Rules (`.exe`, `.com`)**: Prevents binaries from running outside `Program Files` and `Windows`.
- **Script Rules (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`)**: Disallows script execution in user-writable directories (`%TEMP%`, `C:\Users\`). Forces PowerShell into **Constrained Language Mode (CLM)**.
- **Windows Installer Rules (`.msi`, `.msp`)**: Blocks unapproved software installations.
- **Packaged App Rules (`.appx`)**: Regulates modern store applications.

---

## 2. Path Rule Bypass Defense

Never whitelist paths like `C:\Windows\*` without denying known user-writable folders inside Windows (e.g., `C:\Windows\Tasks`, `C:\Windows\Temp`). Prefer **Publisher (Digital Signature)** rules over path rules.
