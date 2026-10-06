---
title: Python Subprocess and Filesystem
platforms: [Linux, Windows]
languages: [Python]
tasks: [Automation, Forensics, Incident Response]
category: Automation
tags: [subprocess, pathlib, hashlib, os.walk, shell injection]
aliases: [run command python, subprocess.run, hash files python, walk directory python, shell=True]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Python Subprocess and Filesystem

## Run a command

```python
import subprocess

result = subprocess.run(
    ["ss", "-lntup"],
    capture_output=True,
    text=True,
    timeout=30,
    check=True,
)
print(result.stdout)
```

| Argument | Effect |
| --- | --- |
| list of args | no shell involved — arguments cannot be injected |
| `capture_output=True` | collect stdout/stderr |
| `text=True` | return `str` instead of `bytes` |
| `check=True` | raise `CalledProcessError` on non-zero exit |
| `timeout=` | raise `TimeoutExpired` instead of hanging |

!!! danger "Avoid `shell=True` with input you did not write"
    `subprocess.run(f"grep {user_input} file", shell=True)` lets `user_input` run arbitrary commands. Pass a list instead.

## Handle failures

```python
try:
    subprocess.run(["systemctl", "is-active", "sshd"], check=True, capture_output=True, text=True)
except subprocess.CalledProcessError as exc:
    print(f"exit {exc.returncode}: {exc.stdout.strip()}")
except FileNotFoundError:
    print("systemctl not installed")
```

## Walk files with pathlib

```python
from pathlib import Path
import time

cutoff = time.time() - 24 * 3600
for path in Path("/tmp").rglob("*"):
    try:
        if path.is_file() and path.stat().st_mtime > cutoff:
            print(path, path.stat().st_size)
    except (PermissionError, FileNotFoundError):
        continue
```

## Hash files (streaming)

```python
import hashlib
from pathlib import Path

def sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
```

Reading in chunks keeps memory flat for large files. Python 3.11+ also offers `hashlib.file_digest(fh, "sha256")`.

## Copy and preserve metadata

```python
import shutil
shutil.copy2("/etc/crontab", "/root/case/crontab")   # copy2 keeps timestamps
```

## Related

- [Python logging and automation](logging-automation.md)
- [Bash scripting](../bash/automation.md)

## Sources

- [subprocess — Python docs](https://docs.python.org/3/library/subprocess.html)
- [pathlib — Python docs](https://docs.python.org/3/library/pathlib.html)
- [hashlib — Python docs](https://docs.python.org/3/library/hashlib.html)
