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
last_verified: 2026-10-12
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

## Install

| Tool | Debian / Ubuntu | RHEL / Fedora (EPEL) | Windows (winget) |
| --- | --- | --- | --- |
| ripgrep | `apt install ripgrep` | `dnf install ripgrep` | `winget install BurntSushi.ripgrep.MSVC` |
| jq | `apt install jq` | `dnf install jq` | `winget install jqlang.jq` |
| yq (Mike Farah) | `snap install yq` or GitHub release | GitHub release | `winget install MikeFarah.yq` |
| fzf | `apt install fzf` | `dnf install fzf` | `winget install junegunn.fzf` |
| fd | `apt install fd-find` (command is `fdfind`) | `dnf install fd-find` | `winget install sharkdp.fd` |

Two different tools are called `yq`. The examples here use Mike Farah's Go version; the Python `yq` (a jq wrapper) has different syntax.

## 1. ripgrep (`rg`) vs grep

Recursively searches directories while respecting `.gitignore` by default, leveraging multi-threaded Rust search:

```bash
# Case-insensitive search across codebases
rg -i "password_hash" /etc/ /var/log/

# Search only inside shell scripts
rg -t sh "systemctl restart"

# Include hidden and ignored files (ignore rules can hide what an attacker dropped)
rg -uu -l "curl .*\| *(ba)?sh" /home /tmp

# Show 2 lines of context, and only file names with a count
rg -C 2 "Failed password" /var/log/auth.log
rg -c "Accepted publickey" /var/log/
```

For incident response, remember that `rg` skips hidden and `.gitignore`d files unless you pass `-uu` (or `-uuu` to also search binary files).

## 2. jq & yq JSON / YAML Processing

```bash
# Extract and format specific JSON keys from API curl response
curl -s https://api.github.com/repos/org/repo/releases/latest | jq -r '.assets[] | {name: .name, size_mb: (.size / 1048576)}'

# Update YAML values in-place
yq -i '.server.port = 8443' config.yaml
```

Security-log examples:

```bash
# AWS CloudTrail: console logins with source IP, as tab-separated text
jq -r '.Records[] | select(.eventName == "ConsoleLogin")
       | [.eventTime, .sourceIPAddress, .userIdentity.arn, .responseElements.ConsoleLogin] | @tsv' cloudtrail.json

# JSON-lines logs (one object per line): count events by type
jq -r '.event_type' events.jsonl | sort | uniq -c | sort -rn

# Read a Kubernetes manifest: every container image
yq '.spec.template.spec.containers[].image' deployment.yaml
```

## 3. fd (find replacement)

```bash
# Files changed in the last 2 days under /etc, including hidden ones
fd -H --changed-within 2d . /etc

# Executables in temp directories (common malware staging)
fd -H -t x . /tmp /var/tmp /dev/shm
```

## 4. fzf (interactive filter)

```bash
# Pick a log file interactively and open it in less
less "$(fd -t f . /var/log | fzf)"

# Search shell history interactively (Ctrl+R after installing fzf key bindings)
history | fzf
```

`fzf` is for interactive use; do not put it in unattended scripts.

## Related

- [Bash overview](index.md)
- [File search and discovery](../../tasks/administration/file-search-discovery.md)

## Sources

- [ripgrep user guide](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md)
- [jq manual](https://jqlang.org/manual/)
- [yq documentation](https://mikefarah.gitbook.io/yq)
- [fd README](https://github.com/sharkdp/fd) · [fzf README](https://github.com/junegunn/fzf)
