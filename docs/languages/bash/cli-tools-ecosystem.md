---
title: Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Administration
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - cli
  - jq
  - ripgrep
  - fzf
  - tools
---

# Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf

High-velocity command-line utilities that replace traditional Unix commands for speed and precision.

## 1. ripgrep (`rg`) vs grep

Recursively searches directories while respecting `.gitignore` by default, leveraging multi-threaded Rust search:

```bash
# Case-insensitive search across codebases
rg -i "password_hash" /etc/ /var/log/

# Search only inside shell scripts
rg -t sh "systemctl restart"
```

## 2. jq & yq JSON / YAML Processing

```bash
# Extract and format specific JSON keys from API curl response
curl -s https://api.github.com/repos/org/repo/releases/latest | jq -r '.assets[] | {name: .name, size_mb: (.size / 1048576)}'

# Update YAML values in-place
yq -i '.server.port = 8443' config.yaml
```
