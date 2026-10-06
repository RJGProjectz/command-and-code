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

# Command & Code CLI Lookup Utility

Fast offline terminal lookup utility for searching knowledge nodes, queries, syntax, and workflows directly from PowerShell, CMD, or Bash without needing a web browser or network connection.

## 1. Purpose & Capabilities

- Instantly search through 195+ knowledge nodes by keyword, task, platform, or language.
- View document contents directly in the terminal via `--cat`.
- Operates entirely offline with zero external dependencies (pure Python + PyYAML).

## 2. Usage Examples

```bash
# Search for brute force or failed authentication workflows
python tools/lookup.py "failed logons"

# Filter by platform and language
python tools/lookup.py "isolate" --platform Windows --language PowerShell

# View the full markdown content of any entry directly in terminal
python tools/lookup.py --cat tasks/incident-response/automated-containment.md
```
