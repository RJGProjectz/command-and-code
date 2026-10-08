---
title: Command & Code CLI Lookup Utility
type: tool
platforms:
  - Windows
  - Linux
languages:
  - Python
tasks:
  - Administration
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - cli
  - search
  - lookup
  - offline
---

# Command & Code Terminal Companion CLI (`cc`)

Fast offline terminal companion CLI for searching knowledge nodes, viewing runbooks, extracting copy-ready command blocks, and executing production automation scripts directly from PowerShell, CMD, or Bash without needing a web browser or network connection.

---

## 1. Purpose & Capabilities

- **Instant Offline Search (`cc find`)**: Search through 263+ knowledge entries by keyword, task, platform, or language with ANSI-colored relevance scoring.
- **Runbook Viewer & Code Extraction (`cc view`)**: Pretty-print any entry directly in your terminal, or extract only executable code blocks with `--code`.
- **Direct Clipboard Copy (`cc copy`)**: Copy specific command blocks directly to the OS clipboard without touching a mouse.
- **Script Discovery & Execution (`cc scripts`, `cc run`)**: Discover and run cataloged PowerShell, Bash, and Python production scripts.
- **Environment Doctor (`cc doctor`)**: Audit local runtime health, Git status, PowerShell version, and schema compliance.

---

## 2. Command Line Reference

```bash
# 1. Search knowledge entries by keywords
cc find "listening ports"
cc find "ransomware" --platform Windows --language PowerShell

# 2. View guide content or extract code blocks
cc view windows-connectivity
cc view ransomware-host-isolation --code

# 3. Copy a specific code block directly to clipboard
cc copy ransomware-host-isolation --block 1

# 4. List and execute cataloged automation scripts
cc scripts vpn
cc run FUNC_PS_TEST_VPN_CONNECTION

# 5. Environment & repository health audit
cc doctor
```

---

## 3. Shell Integration

To use `cc` globally from any directory:

### Windows PowerShell
Add this function to your PowerShell profile (`$PROFILE`):
```powershell
function cc { & "g:\AI-Playground\C&C\command-and-code\tools\cc.cmd" @args }
```

### Linux / macOS Bash
Add an alias to your `~/.bashrc` or `~/.zshrc`:
```bash
alias cc="/path/to/command-and-code/tools/cc.sh"
```
