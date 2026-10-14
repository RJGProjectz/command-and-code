---
title: "Cross-platform data handling: Windows ↔ Linux, secrets, encodings and transport"
type: entry
platforms: [Windows, Linux, Proxmox]
languages: [Python, PowerShell, Bash]
tasks: [Administration, Automation, Troubleshooting, Hardening]
category: Systems
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [crlf, line-endings, encoding, utf-8, bom, secrets, chpasswd, subprocess, quoting, clipboard, ssh, time, locale, yaml, csv, json, ndjson, cross-platform]
aliases: [CRLF vs LF, Line Endings, Text vs Binary Mode, UTF-8 BOM, Secrets in argv, Verify effects not exit codes, bad interpreter ^M]
difficulty: intermediate
verified: true
last_verified: 2026-10-14
---

# Cross-platform data handling: Windows ↔ Linux, secrets, encodings and transport
> **Created**: 2026-10-12T21:30:00Z
> **Last Modified**: 2026-10-14T14:00:00Z
> **Author**: RJGProjectz

!!! info "How this page was checked"
    Windows-side behaviour (Python 3.11 `subprocess`, Windows PowerShell 5.1 and PowerShell 7.6 pipes, file encodings,
    clipboard lengths, `ConvertTo-Json` depth, culture parsing, PyYAML typing) was reproduced on Windows 11 on 2026-10-12.
    Linux side, checked 2026-10-14: GNU `sed`, `iconv`, `date`, `sha256sum`, `tr` and `od` examples run in GNU tools;
    `chpasswd` behaviour checked against the shadow-utils man page and source (only `
` is stripped, so `` stays in
    the password); the Proxmox ticket call checked against the Proxmox VE API documentation, and the `curl
    --data-urlencode 'password@-'` form tested against a local endpoint.

**In one line:** the bytes that arrive are not always the bytes you sent. Every hop (interpreter, shell, pipe, file,
clipboard, terminal, HTTP) can add, drop or re-encode characters, and most tools still report success.

## The incident this page comes from

A Python script on a Windows admin workstation set the Linux `root` password on 4 Proxmox nodes. It piped
`root:<password>\n` into `ssh <node> chpasswd` with `subprocess.run(..., input=..., text=True)`. In text mode on
Windows, Python writes `\n` to the child's stdin as `\r\n`. `chpasswd` removes the trailing `\n` and keeps the rest, so
it stored `<password>\r` and exited `0`. After that nobody could log in with a password, either in the Proxmox web UI
or over SSH. The vault held the correct 24-character value, so everyone suspected the vault, the keyboard layout or a
typo. Key-based SSH still worked, and that is how the nodes were recovered.

**Fix:** send stdin as bytes (`input=data.encode()`, no `text=True`), strip CR on the Linux side as defence in depth,
then check the result with a real login rather than the exit code.

## Executive summary

- **Send bytes, not text, across a process boundary.** Text mode, PowerShell pipes to native programs and `>`
  redirection all change line endings and encoding on Windows. Encode once, explicitly, and pass the bytes.
- **Secrets travel on stdin or in a protected file, never in argv, URLs or logs.** Validate them before use: exact
  length, allowed characters, no `\r`, `\n` or `\0`, and no delimiters the receiving tool parses.
- **Exit code 0 means the tool ran, not that the data is right.** After a change, check the effect itself: log in,
  read the value back, query the record you just wrote.
- **Fix the format at the edges.** Use `.gitattributes` `eol=lf` for anything Linux executes, UTF-8 without a BOM,
  ISO 8601 timestamps with an offset, the invariant culture for numbers, and quoted YAML strings.
- **Rotate credentials with a way back.** Keep the previous vault version, keep a second access path (an SSH key and an
  open session), change one node first, test with a fresh login, and only then close the spare session.

## Assumptions

- Admin workstation: Windows 10/11, Python 3.8 or newer, Windows PowerShell 5.1 and PowerShell 7.x. Targets: Linux
  with GNU coreutils and OpenSSH. macOS notes are given where BSD tools differ.
- "PowerShell 5.1" means Windows PowerShell 5.1 (.NET Framework). "PowerShell 7" means 7.x (.NET), on Windows unless
  stated otherwise.
- Example names (`pve1`, `root@pam`, `/etc/pve/pve-root-ca.pem`) are placeholders for your own nodes and paths.
- Statements about third-party behaviour describe the documented or observed default. Check the version you run.

---

## 1. Line endings: CRLF vs LF

**Rule.** Anything Linux reads (scripts, units, configs, stdin data) must contain LF only. On Windows, open files and
pipes in binary mode, or give an explicit `newline="\n"`. Git stores `*.sh`, `*.py`, `*.service` and `*.conf` with
`eol=lf`.

**Why.** Windows text mode writes `\n` as `\r\n`. The default places where this happens:

| Layer | What it does on Windows | Verified |
| :--- | :--- | :--- |
| Python `subprocess.run(input=str, text=True)` | Writes `\n` to the child's stdin as `\r\n` | Yes (3.11) |
| Python `open(p, "w")` | Writes `\n` as `\r\n` unless `newline="\n"` | Documented |
| Python `csv` writer on a file opened without `newline=""` | Produces `\r\r\n` (blank rows) | Documented |
| PowerShell 5.1 and 7: `'text' \| native.exe` | Sends each string followed by `\r\n` | Yes |
| PowerShell `>`, `Out-File`, `Set-Content` | End every line with `\r\n` (`-NoNewline` drops the last one) | Yes |
| Here-string in a `.ps1` saved with CRLF | The string itself contains `\r\n` | Yes |
| Git `core.autocrlf=true` | Converts LF to CRLF in the working tree on checkout | Documented |
| Editors and copy/paste from Windows | Save or paste CRLF | Varies |

**How it shows up.** These symptoms point you the wrong way:

| Symptom | What actually happened |
| :--- | :--- |
| `/bin/bash^M: bad interpreter: No such file or directory` | The shebang line ends in `\r`, so the kernel looks for `/bin/bash\r` |
| `$'\r': command not found`, `syntax error near unexpected token $'do\r'` | Bash runs `\r` as part of a command |
| A password "set successfully" never works | The stored value has a trailing `\r` (the incident above) |
| `systemd` reports a bad setting or ignores a value | The unit file has CRLF, so the value contains `\r` |
| A variable compares unequal although it prints the same | Invisible `\r` at the end (`[ "$a" = "yes" ]` fails) |
| `curl: (3) URL rejected` or a 404 on a URL read from a file | Trailing `\r` in the URL |

**Wrong.**

```python
# Windows: the child receives b"root:<pw>\r\n"
subprocess.run(["ssh", "pve1", "chpasswd"], input=f"root:{pw}\n", text=True, check=True)
```

```powershell
# 5.1 and 7: chpasswd receives "root:<pw>`r`n"
"root:$pw" | ssh pve1 chpasswd
```

**Right.**

=== "Python"

    ```python
    import subprocess

    def send_stdin_bytes(cmd: list[str], payload: str) -> subprocess.CompletedProcess:
        """Run cmd with payload on stdin as UTF-8 bytes. No newline translation, on any OS."""
        return subprocess.run(cmd, input=payload.encode("utf-8"), capture_output=True, check=True)

    # Strip CR on the Linux side too (defence in depth). The secret goes on stdin, not in argv.
    send_stdin_bytes(["ssh", "pve1", "tr -d '\\r' | chpasswd"], f"root:{pw}\n")

    # Files Linux will read:
    with open("deploy.sh", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(script_text)
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    # Writes raw bytes to a native program's stdin. Works the same on 5.1 and 7.
    function Invoke-NativeStdinBytes {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$FilePath,
            [Parameter(Mandatory)][string]$Arguments,      # no secrets here: argv is visible
            [Parameter(Mandatory)][byte[]]$InputBytes
        )
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEndAsync()
        $stderr = $proc.StandardError.ReadToEndAsync()
        $proc.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length)
        $proc.StandardInput.Close()
        $proc.WaitForExit()
        [pscustomobject]@{ ExitCode = $proc.ExitCode; StdOut = $stdout.Result; StdErr = $stderr.Result }
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes("root:$plain`n")   # explicit LF
    $result = Invoke-NativeStdinBytes -FilePath 'ssh' -Arguments 'pve1 "tr -d ''\r'' | chpasswd"' -InputBytes $bytes
    if ($result.ExitCode -ne 0) { throw "chpasswd failed: $($result.StdErr)" }

    # A whole file, byte for byte (PowerShell has no '<' redirection):
    $proc = Start-Process -FilePath 'ssh' -ArgumentList 'pve1', 'bash -s' -RedirectStandardInput '.\deploy.sh' `
        -NoNewWindow -Wait -PassThru
    ```

=== "Bash"

    ```bash
    # printf is a builtin: the password never appears in a process argv.
    printf 'root:%s\n' "$pw" | ssh pve1 "tr -d '\r' | chpasswd"

    # Repair files that already have CRLF
    dos2unix deploy.sh                 # if installed
    sed -i 's/\r$//' deploy.sh         # GNU sed; on macOS: sed -i '' $'s/\r$//' deploy.sh
    tr -d '\r' < in.txt > out.txt      # removes every CR, not only those before LF
    ```

**Git.** Commit a `.gitattributes` and stop relying on each person's `core.autocrlf`:

```gitattributes
* text=auto
*.sh       text eol=lf
*.bash     text eol=lf
*.py       text eol=lf
*.service  text eol=lf
*.timer    text eol=lf
*.conf     text eol=lf
*.yml      text eol=lf
*.yaml     text eol=lf
Dockerfile text eol=lf
*.ps1      text eol=crlf
*.bat      text eol=crlf
*.cmd      text eol=crlf
*.png      binary
```

After adding it, run `git add --renormalize .` once and commit the result.

**How to test it.**

```bash
file deploy.sh                      # "... with CRLF line terminators"
grep -c $'\r' deploy.sh             # count of lines containing CR (0 is good)
cat -A deploy.sh | head             # CR shows as ^M before the $
git ls-files --eol                  # i/lf w/crlf = stored LF, checked out CRLF
```

```python
# Unit test: the exact bytes a child receives
import subprocess, sys
probe = [sys.executable, "-c", "import sys; sys.stdout.write(repr(sys.stdin.buffer.read()))"]
out = subprocess.run(probe, input=b"root:x\n", capture_output=True).stdout
assert out == b"b'root:x\\n'", out
```

```powershell
'x' | python -c "import sys; print(repr(sys.stdin.buffer.read()))"   # shows b'x\r\n' in 5.1 and 7
```

---

## 2. Secrets in transit

**Rule.** Pass a secret on **stdin** or through a **file readable only by its owner**. Never put it in argv, URLs,
log lines or exception text. An environment variable is acceptable only for a short-lived child you start yourself.
Before you use a secret, validate it: exact expected length, allowed character set, no control characters, and no
delimiter that the receiving tool parses.

**Why: where each channel leaks.**

| Channel | Who can see it | Typical leak |
| :--- | :--- | :--- |
| argv / command line | Linux: any local user through `ps` and `/proc/<pid>/cmdline` (unless `/proc` is mounted with `hidepid`). Windows: Security event 4688 when command-line auditing is on, Sysmon event 1, EDR telemetry | `sshpass -p`, `mysql -p<pw>`, `curl -u user:pw`, `subprocess.CalledProcessError` text (it prints the full argv) |
| Shell history | The user, backups, anyone who reads the home directory | `~/.bash_history`; PSReadLine history (`(Get-PSReadLineOption).HistorySavePath`) |
| PowerShell logging | SIEM readers | Script block logging (event 4104) and transcription record script text, including literal secrets |
| Environment variables | The same user and root (`/proc/<pid>/environ`), every child process, crash reports, `docker inspect` | Inherited by every tool you start afterwards |
| URLs and query strings | Proxies, web server access logs, browser history, the `Referer` header | `?token=...`, `https://user:pw@host` |
| Logs and debug output | Everyone with log access, the SIEM, ticket attachments | `set -x`, `print(cmd)`, verbose HTTP logging |
| Crash dumps and tracebacks | Support staff, error trackers | Tracebacks that show local variables, process memory dumps |
| Temporary files | Other users if permissions are loose; backups | World-readable `/tmp/pw.txt`, files that are never deleted |
| stdin | The receiving process only | Low risk. The parent must not log what it sends |

**Trimming rules.**

- Remove **only CR and LF, and only at the ends**: Python `s.strip("\r\n")`, PowerShell `$s.Trim("`r", "`n")`,
  Bash `s=${s%$'\n'}; s=${s%$'\r'}`.
- Never use a bare `strip()` or `Trim()`. Spaces and tabs can be legitimate characters in a secret.
- After trimming, **reject** anything that still contains `\r`, `\n` or `\0`. Do not try to repair it silently.

**Validation.** Check the value against what the vault says it should be, not just against "not empty".

| Check | Example rule | Why |
| :--- | :--- | :--- |
| Length | Equal to the vault's recorded length (24 in the incident) | Catches added `\r`, truncation, a lost character |
| Character set | `[A-Za-z0-9!#%+,.;=?@^_~-]` or your generator's alphabet | Catches mojibake and keyboard-layout swaps |
| Forbidden characters | No `\r`, `\n`, `\0` or other control characters (< 0x20, 0x7F) | Line-based tools cut or keep them silently |
| Tool delimiters | `chpasswd`: no `:` in the user name and no newline anywhere. A `:` inside the password is kept (shadow-utils splits at the first `:`) | The tool splits on these characters |
| Encoding | ASCII-only for anything typed into consoles, IPMI, VNC or boot prompts | Layout-dependent characters break at the console |

**Wrong.**

```python
subprocess.run(["sshpass", "-p", pw, "ssh", "pve1", "true"], check=True)  # argv: visible, and in the exception
requests.get(f"https://pve1:8006/api?password={pw}")                       # URL: logged
logging.info("running %s", cmd)                                            # cmd may contain the secret
```

**Right.**

=== "Python"

    ```python
    import re

    ALLOWED = re.compile(r"[A-Za-z0-9!#%+,.;=?@^_~-]+")
    FORBIDDEN = {"\r", "\n", "\0"}

    def validate_secret(value: str, expected_len: int, *, forbid: str = ":") -> str:
        value = value.strip("\r\n")                      # edges only, CR/LF only
        if any(ch in value for ch in FORBIDDEN) or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("secret contains control characters")
        if len(value) != expected_len:
            raise ValueError(f"secret length {len(value)} != expected {expected_len}")   # length only, never the value
        if not ALLOWED.fullmatch(value) or any(ch in value for ch in forbid):
            raise ValueError("secret contains characters outside the allowed set")
        return value
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    function Test-SecretValue {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Value,
            [Parameter(Mandatory)][int]$ExpectedLength,
            [string]$Forbid = ':'
        )
        $v = $Value.Trim([char]13, [char]10)
        if ($v -match '[\x00-\x1F\x7F]') { throw 'secret contains control characters' }
        if ($v.Length -ne $ExpectedLength) { throw "secret length $($v.Length) != expected $ExpectedLength" }
        if ($v -cnotmatch '^[A-Za-z0-9!#%+,.;=?@^_~-]+$') { throw 'secret contains characters outside the allowed set' }
        if ($Forbid -and $v.IndexOfAny($Forbid.ToCharArray()) -ge 0) { throw 'secret contains a delimiter' }
        $v
    }
    # SecureString -> plain text only at the moment of use, then clear the reference
    $plain = [System.Net.NetworkCredential]::new('', $secure).Password
    ```

=== "Bash"

    ```bash
    IFS= read -rs pw < /dev/tty               # no echo, no history, no argv
    pw=${pw%$'\r'}
    [[ $pw == *[[:cntrl:]]* || $pw == *:* ]] && { echo "invalid secret" >&2; exit 1; }
    (( ${#pw} == 24 )) || { echo "length ${#pw} != 24" >&2; exit 1; }
    # Files: create them private from the start
    ( umask 077; printf '%s' "$pw" > "$XDG_RUNTIME_DIR/pw" )
    export HISTCONTROL=ignorespace            # a leading space keeps a command out of history
    ```

**Credential rotation with rollback.** Use this for root, service accounts and API keys:

| Step | Action | Pass condition |
| :--- | :--- | :--- |
| 1 | Prove a second access path: `ssh -o BatchMode=yes -o PasswordAuthentication=no root@pve1 true` | Exit 0 with key authentication only |
| 2 | Open a spare root session on the target and **leave it open** | Prompt is available |
| 3 | Store the new value in the vault as a **new version**. Keep the previous version | Both versions are readable |
| 4 | Validate the new value locally (length, character set, forbidden characters) | Validator passes |
| 5 | Apply to **one** node (canary) with bytes on stdin | Exit 0 (necessary, not sufficient) |
| 6 | Test with a **new** password login: API ticket and/or interactive SSH (Section 3) | Login succeeds |
| 7 | On failure: restore the previous version over the key path, then investigate | Old password works again |
| 8 | Repeat steps 5–6 for each remaining node. On Proxmox, `root@pam` lives in each node's own `/etc/shadow`, so every node needs its own change and its own test | All nodes pass |
| 9 | Close the spare sessions. Mark the new vault version as current | Recorded in the change log |

**How to test it.**

```bash
# argv leak check while your script runs (Linux). The pattern arrives through a file descriptor,
# so the check itself does not put part of the secret into grep's argv.
grep -lF -f <(printf '%s\n' "${pw:0:6}") /proc/[0-9]*/cmdline 2>/dev/null    # should print nothing
# Do the logs contain the secret? Search for a short prefix, never the full value
grep -rlF -f <(printf '%s\n' "${pw:0:6}") /var/log/ 2>/dev/null | head
```

```powershell
# Windows: does any recent 4688 event contain the tool name with a password flag?
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddHours(-1) } |
    Where-Object { $_.Message -match 'sshpass|-p\s|--password' } | Select-Object -First 5 TimeCreated
```

---

## 3. Verify effects, not exit codes

**Rule.** After every state change, check the **effect itself** through an independent path: log in, read the value
back, query the record you wrote, call the service. An exit code tells you the tool did not crash. It does not tell
you the data is right.

**Why.** These tools succeed while doing something other than what you meant:

| Tool | Reports | What can be wrong |
| :--- | :--- | :--- |
| `chpasswd` | Exit 0 | Stores the password with a stray `\r` or with the wrong encoding |
| `usermod -p <value>` | Exit 0 | `-p` expects an **already hashed** value. Plain text is written to `/etc/shadow` as-is, so no password ever matches |
| `curl` without `--fail` | Exit 0 on HTTP 4xx and 5xx | The error body is ignored |
| HTTP 200 from a bulk API | Success | Elasticsearch `_bulk` returns 200 with `"errors": true` and a failure for each rejected item |
| Log ingestion (VictoriaLogs, Elasticsearch, Splunk HEC) | 2xx | Body parsed differently than intended: a JSON array sent to a JSON-lines endpoint, the wrong time field, or every field ending up in one message string |
| `systemctl restart` | Exit 0 | For `Type=simple`, the unit can crash a second later |
| `cmd \| tee log` in Bash | Exit status of `tee` | The failure of `cmd` is hidden unless `set -o pipefail` |
| Native programs in PowerShell | `$LASTEXITCODE` set, no exception | The script continues after a failure. 7.4+ can throw with `$PSNativeCommandUseErrorActionPreference = $true` |
| `ssh host cmd` | Exit status of the remote command | A remote pipeline without `pipefail` hides failures |
| `robocopy` | Non-zero exit code | The opposite case: codes 1–7 mean success with changes, 8 and above mean failure |

**Wrong.**

```python
r = subprocess.run(["ssh", node, "chpasswd"], input=data, text=True)
if r.returncode == 0:
    print("password rotated")          # the claim is unproven
```

**Right: check with a real login, from a new connection.**

=== "Python"

    ```python
    import json, ssl, urllib.error, urllib.parse, urllib.request

    def pve_login_ok(node: str, user: str, password: str, cafile: str) -> bool:
        """True only if the Proxmox API issues a ticket for these credentials."""
        body = urllib.parse.urlencode({"username": user, "password": password}).encode("ascii")
        req = urllib.request.Request(f"https://{node}:8006/api2/json/access/ticket", data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        ctx = ssl.create_default_context(cafile=cafile)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                return bool(json.load(resp).get("data", {}).get("ticket"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return False
            raise

    if not pve_login_ok("pve1", "root@pam", pw, "pve-root-ca.pem"):
        raise SystemExit("rotation FAILED on pve1 - roll back over the key path")
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    # The node's CA must be trusted by the workstation (5.1 has no -SkipCertificateCheck; do not disable validation).
    $body = @{ username = 'root@pam'; password = $plain }
    try {
        $r = Invoke-RestMethod -Method Post -Uri 'https://pve1:8006/api2/json/access/ticket' -Body $body
        if (-not $r.data.ticket) { throw 'no ticket returned' }
    } catch {
        throw "rotation FAILED on pve1 - roll back over the key path ($($_.Exception.Message))"
    }
    ```

=== "Bash"

    ```bash
    # The password goes in on stdin; printf adds no newline. --fail turns 401 into a non-zero exit.
    printf '%s' "$pw" | curl --fail --silent --show-error --cacert pve-root-ca.pem \
        --data-urlencode 'username=root@pam' --data-urlencode 'password@-' \
        https://pve1:8006/api2/json/access/ticket | grep -q '"ticket"' \
        || { echo "rotation FAILED on pve1" >&2; exit 1; }

    # The human path: force password authentication in a NEW session and type the value
    ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password root@pve1 true
    ```

**Other post-change checks.**

```bash
set -euo pipefail                                    # pipeline failures are not hidden
curl --fail-with-body -sS ...                        # curl 7.76+: non-zero exit on 4xx/5xx, and the body is kept
curl -sS -XPOST host:9200/_bulk -H 'Content-Type: application/x-ndjson' --data-binary @batch.ndjson \
  | jq -e '.errors == false'                         # fails if any item was rejected
systemctl restart app && sleep 5 && systemctl is-active --quiet app
```

**How to test it.** Every change script ends with an assertion that reads the state back and fails loudly. In code
review, look for the words "success", "done" or "rotated" printed right after a call that only checked the exit code.

---

## 4. Character encodings and BOMs

**Rule.** Use UTF-8 **without a BOM** for everything machines read: scripts, JSON, YAML, configs, CSV for tools, and
hash inputs. Always name the encoding when you read or write. The one common exception: CSV meant for Excel often
needs a BOM (`utf-8-sig`).

**Why.** The defaults differ between interpreters and versions:

| Writer | Default encoding | BOM | Verified |
| :--- | :--- | :--- | :--- |
| PowerShell 5.1 `>` and `Out-File` | UTF-16LE | Yes (`FF FE`) | Yes |
| PowerShell 5.1 `Set-Content` | ANSI code page (for example cp1252) | No | Yes |
| PowerShell 5.1 `Out-File -Encoding utf8` | UTF-8 | **Yes** (`EF BB BF`) | Yes |
| PowerShell 5.1 `Export-Csv` | ASCII (non-ASCII becomes `?`) | No | Documented |
| PowerShell 5.1 pipe to native (`$OutputEncoding`) | US-ASCII | — | Yes |
| PowerShell 7 `>`, `Out-File`, `Set-Content`, `Export-Csv` | UTF-8 (`utf8NoBOM`) | No | Yes |
| PowerShell 7 pipe to native (`$OutputEncoding`) | UTF-8 | — | Yes |
| Python `open()` without `encoding=` | Locale encoding (cp1252 on a US/Western Windows) | No | Yes (3.11) |
| Python with `PYTHONUTF8=1` or `-X utf8` | UTF-8 | No | Documented |
| Linux tools under a `*.UTF-8` locale | UTF-8 | No | — |

PEP 686 makes Python's UTF-8 mode the default starting with Python 3.15. Until every interpreter you run is that new,
pass `encoding=` explicitly.

**How it shows up.**

| You see | Most likely cause |
| :--- | :--- |
| `Ã©` instead of `é` | UTF-8 bytes decoded as cp1252 or Latin-1 |
| `ï»¿` at the start of a file or the first CSV header | A UTF-8 BOM decoded as cp1252 |
| `�` (U+FFFD) | Invalid bytes replaced during decoding (`errors="replace"`): the data is already lost |
| Spaces or `\x00` between every character; `grep` finds nothing | A UTF-16LE file read as an 8-bit encoding |
| `é` shows as `Θ` or `Ú` in a console | OEM console code page (437/850) instead of 65001 |
| `Unexpected UTF-8 BOM (decode using utf-8-sig)` | Python `json` given a string that starts with U+FEFF (verified) |
| Line 1 of a script fails with odd characters before `#!` | A BOM before the shebang: the kernel does not see `#!` |
| The same text has different SHA-256 values on two hosts | BOM or encoding differs (see Section 8) |
| `UnicodeEncodeError: ... surrogates not allowed` | Undecodable bytes carried as lone surrogates (`surrogateescape`) and then written out as UTF-8 |
| First YAML key not found; first CSV column is named `\ufeffname` | A BOM became part of the first key |

**Wrong.**

```powershell
$config | ConvertTo-Json | Out-File config.json                    # 5.1: UTF-16LE with BOM; many parsers fail
"#!/bin/bash`n..." | Out-File -Encoding utf8 run.sh                # 5.1: BOM before the shebang
```

```python
data = open("export.csv").read()                                   # cp1252 on Windows, UTF-8 on Linux
```

**Right.**

=== "Python"

    ```python
    from pathlib import Path
    Path("config.json").write_text(text, encoding="utf-8", newline="\n")
    text = Path("maybe-bom.json").read_text(encoding="utf-8-sig")     # accepts input with or without a BOM
    subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="strict")   # fail, do not replace
    # Whole process: set PYTHONUTF8=1 in the environment, or run python -X utf8
    ```

=== "PowerShell 5.1"

    ```powershell
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Join-Path $PWD 'config.json'), ($text -replace "`r`n", "`n"), $utf8NoBom)
    $OutputEncoding = $utf8NoBom                                     # pipes to native programs
    [Console]::OutputEncoding = $utf8NoBom                           # decoding native output
    ```

=== "PowerShell 7"

    ```powershell
    Set-Content -LiteralPath config.json -Value $text -Encoding utf8NoBOM -NoNewline
    # 'utf8' is already BOM-less in 7; 'utf8BOM' adds one when Excel needs it
    $PSDefaultParameterValues['*:Encoding'] = 'utf8NoBOM'           # do NOT copy this line into 5.1: there 'utf8' adds a BOM
    ```

=== "Bash"

    ```bash
    export LANG=C.UTF-8 LC_ALL=C.UTF-8          # or en_US.UTF-8 if C.UTF-8 is not available
    iconv -f UTF-16LE -t UTF-8 in.txt | sed '1s/^\xEF\xBB\xBF//' > out.txt   # GNU sed
    ```

**Console code pages.** `chcp 65001` switches a `cmd` console to UTF-8. In PowerShell, set
`[Console]::OutputEncoding` as shown above. The Windows "Beta: Use Unicode UTF-8 for worldwide language support"
option changes the code page for the whole system. That is an owner decision, not a script step.

**How to test it.**

```bash
file -bi config.json                            # charset=utf-8 / utf-16le
head -c 3 file | od -An -tx1                    # ef bb bf = UTF-8 BOM, ff fe = UTF-16LE BOM
iconv -f UTF-8 -t UTF-8 file > /dev/null        # non-zero exit = not valid UTF-8
grep -naxv '.*' file                            # lines with invalid UTF-8 (UTF-8 locale)
```

```powershell
$b = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath .\config.json).ProviderPath)
'{0:X2} {1:X2} {2:X2}' -f $b[0], $b[1], $b[2]
```

```python
assert not Path(p).read_bytes().startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")), f"BOM in {p}"
```

---

## 5. The clipboard as a transport

**Rule.** Treat the clipboard as an untrusted, lossy and logged channel. For secrets, prefer the password manager's
own autofill or a stdin pipe. If you must paste, check the **length** (and the character classes) at the receiving
end. Never trust that it looks right.

**Why.**

| Hazard | Detail |
| :--- | :--- |
| Added newline | `'p@ss' \| clip.exe` puts 6 characters on the clipboard (`p@ss` plus CRLF) in 5.1 and 7. `Set-Clipboard -Value 'p@ss'` puts 4. Verified |
| Encoding loss | PowerShell 5.1 pipes to `clip.exe` as US-ASCII, so non-ASCII characters can arrive as `?` |
| Line splitting | Windows PowerShell 5.1 `Get-Clipboard` without `-Raw` returns an array of lines; use `-Raw` to get the exact text |
| History and sync | Windows clipboard history (Win+V) and cloud clipboard keep copies; so do clipboard managers on Linux and macOS |
| Auto-clear | Password managers clear the clipboard after a timeout, which may happen before a slow remote paste completes |
| Autofill and auto-type | An auto-type sequence can add `{TAB}` or `{ENTER}`. Pasting into a field that already contains text adds to that text |
| Silent truncation | An HTML `maxlength` attribute or a fixed-width console field cuts a pasted value without warning |
| Remote consoles | RDP clipboard redirection can be disabled by policy. A noVNC or IPMI text console types the value as key presses, so keyboard-layout differences (`y`/`z`, `@`, `"`, `\`, `\|`) change characters |

**Wrong.** Copy the password from the vault, paste it into the Proxmox noVNC console of a node with a different
keyboard layout, see dots, and assume it went in correctly.

**Right.**

=== "Python"

    ```python
    # Avoid the clipboard entirely: read with no echo and send on stdin.
    import getpass
    pw = validate_secret(getpass.getpass("New root password: "), expected_len=24)
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    Set-Clipboard -Value $value                       # exact text, no newline added
    $got = Get-Clipboard -Raw
    if ($got.Length -ne $value.Length) { throw "clipboard length $($got.Length) != $($value.Length)" }
    Set-Clipboard -Value ' '                          # overwrite when done (history may still keep a copy)
    ```

=== "Bash"

    ```bash
    printf '%s' "$value" | xclip -selection clipboard     # X11; wl-copy on Wayland; pbcopy on macOS (no newline added)
    # On the receiving Linux host: check what was actually pasted, without echoing it
    IFS= read -rs got; printf '%s' "$got" | wc -c
    ```

**How to test it.** Paste into a length check, never into a plain-text field "to have a look". Count the characters
(`wc -c` on Linux, `.Length` in PowerShell) and compare with the vault's recorded length. For console-typed values,
test once with a known non-secret string that contains the risky characters (`@"\|yz`).

---

## 6. Quoting and escaping across layers

**Rule.** Do not hand-nest quotes across `ssh`, `bash` and PowerShell. Send scripts over **stdin**
(`ssh host 'bash -s' < script.sh`), pass data as **arguments quoted once with a library function** (`shlex.join`,
`printf %q`), and use **literal** here-strings and heredocs unless you really need expansion.

**Why.**

- `ssh host a b c` joins its arguments with spaces and the **remote** shell parses the result again. Every layer
  removes one level of quoting.
- Windows PowerShell 5.1 (and PowerShell up to 7.2) drops or mangles embedded double quotes when it passes arguments
  to native programs. PowerShell 7.3 and later pass them correctly (`$PSNativeCommandArgumentPassing`, with
  exceptions for some programs such as `cmd.exe` and `.bat` files).
- Escapes are interpreted by whichever layer writes the text. A Python string `"\n"`, a PowerShell `` "`n" ``,
  `echo -e` and `printf` all turn `\n` into a real newline, which breaks the generated script.
- Unquoted heredocs (`<<EOF`) expand `$var` and `$(...)` **locally**, before `ssh` sends anything.
- PowerShell has no `<` input redirection, and piping a string adds CRLF (Section 1).

**Wrong.**

```bash
ssh pve1 "echo $HOME"                        # expands on the workstation, not on pve1
ssh pve1 bash <<EOF
for f in $(ls /etc/pve/nodes); do echo $f; done
EOF
# $(ls ...) runs on the workstation
```

```python
script = f"printf 'a\nb'\n"                  # Python turns \n into a newline inside printf's argument
```

```powershell
ssh pve1 'grep "two words" /etc/hosts'       # 5.1: the inner double quotes are lost
Get-Content -Raw .\fix.sh | ssh pve1 'bash -s'   # adds a CRLF at the end; CRLF from the file stays as well
```

**Right.**

=== "Python"

    ```python
    import shlex, subprocess
    from pathlib import Path

    remote = shlex.join(["bash", "-s", "--", vmid, label])         # quoted once, for the remote shell
    subprocess.run(["ssh", "pve1", remote], input=Path("fix.sh").read_bytes(), check=True)

    script = r"printf 'a\nb'" + "\n"                                 # raw string keeps the backslash
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    # The script file goes byte for byte on stdin; arguments are simple tokens
    $p = Start-Process -FilePath 'ssh' -ArgumentList 'pve1', 'bash -s -- 101 nightly' `
        -RedirectStandardInput '.\fix.sh' -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "remote script failed: $($p.ExitCode)" }

    $literal = @'
    echo "$HOME stays literal here; `n is not an escape"
    '@
    $literal = $literal -replace "`r`n", "`n"                         # if the .ps1 was saved with CRLF
    ```

=== "Bash"

    ```bash
    ssh pve1 'bash -s' < fix.sh                                       # no quoting of the script at all
    ssh pve1 "bash -s -- $(printf '%q ' "$vmid" "$label")" < fix.sh   # arguments quoted once
    ssh pve1 bash <<'EOF'                                             # quoted delimiter: nothing expands locally
    for f in /etc/pve/nodes/*; do echo "$f"; done
    EOF
    ```

**How to test it.** Run the remote side with `bash -x -s` once on a lab node and read the trace. Add a self-check
at the top of the remote script: `printf '%s\n' "$@" | od -c | head` shows exactly what arrived, including stray
`\r`. For generated scripts, run `bash -n` (syntax check) on the target before you execute them.

---

## 7. Paths and environments

**Rule.** Build paths with the language's path API, never by string concatenation. Know which interpreter you are in
(native Windows, Git Bash/MSYS, WSL, Linux). Get scratch directories from the API (`tempfile`,
`[IO.Path]::GetTempPath()`), not from `/tmp` or `$env:TEMP` written into the code.

**Why.**

| Environment | `C:\Users\me\x` appears as | `/tmp` is | Notes |
| :--- | :--- | :--- | :--- |
| Windows (cmd, PowerShell, native Python) | `C:\Users\me\x` (`/` also accepted by most APIs) | Not a path | `%TEMP%` = `C:\Users\me\AppData\Local\Temp` |
| Git Bash (MSYS2) | `/c/Users/me/x` | Usually mapped to the Windows user temp folder | Converts arguments that look like paths before calling native programs (`MSYS_NO_PATHCONV=1` turns this off) |
| WSL | `/mnt/c/Users/me/x` | The distro's own `/tmp` | Windows sees WSL files at `\\wsl.localhost\<distro>\`; convert with `wslpath` |
| Linux and macOS | — | `/tmp` (may be tmpfs, may be cleaned at boot) | macOS `$TMPDIR` is a per-user folder |

Other differences:

- **Case.** Linux is case-sensitive. NTFS and default macOS APFS are case-insensitive but preserve case. Two files
  that differ only in case break a checkout on Windows and macOS.
- **Length.** Classic Windows `MAX_PATH` is 260 characters. Long paths need the system `LongPathsEnabled` setting (an
  owner action) and an application that supports them; Git needs `core.longpaths=true`. On Linux, `NAME_MAX` is
  255 **bytes** per name, so multi-byte UTF-8 names hit the limit sooner.
- **Characters.** Windows forbids `<>:"/\|?*`, names that end in a dot or a space, and reserved names (`CON`, `NUL`,
  `COM1`, …). A Linux file such as `backup-10:00.tar` cannot be checked out on Windows.
- **Wildcards.** PowerShell `-Path` treats `[` and `]` as wildcards: use `-LiteralPath`.
- **Spaces.** Quote every expansion: `"$f"` in Bash, `-LiteralPath $f` in PowerShell, a list (not a string) for
  Python `subprocess`.
- **MSYS conversion.** In Git Bash, `cmd /c dir` becomes `cmd C:/ dir`; write `cmd //c dir`. An argument such as
  `/p:Config=Release` can also be rewritten.

**Wrong.**

```python
out = "C:\\scratch\\" + name + ".json"        # breaks on Linux, and a name containing ".." escapes the folder
open("/tmp/report.txt", "w")                  # not a real location for native Windows Python
```

**Right.**

=== "Python"

    ```python
    import tempfile
    from pathlib import Path

    base = Path(tempfile.gettempdir()) / "cc-scratch"
    base.mkdir(parents=True, exist_ok=True)
    out = (base / f"{name}.json").resolve()
    if base.resolve() not in out.parents:
        raise ValueError("path escapes scratch directory")
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    $base = Join-Path ([System.IO.Path]::GetTempPath()) 'cc-scratch'   # $env:TEMP does not exist on Linux
    $null = New-Item -ItemType Directory -Path $base -Force
    $out = Join-Path $base "$name.json"
    Get-Item -LiteralPath $out -ErrorAction SilentlyContinue
    ```

=== "Bash"

    ```bash
    scratch=$(mktemp -d)                       # honours $TMPDIR
    trap 'rm -rf -- "$scratch"' EXIT
    win=$(cygpath -w "$scratch" 2>/dev/null || wslpath -w "$scratch" 2>/dev/null || echo "$scratch")
    ```

**How to test it.** Run the test suite on Windows and Linux (CI matrix). Include fixtures with spaces, a `[1]` in a
name, non-ASCII characters and a long path. Run `git ls-files | sort -f | uniq -di` to find names that differ only in
case.

---

## 8. Hashing and drift detection

**Rule.** For **drift** detection on text (configs, scripts, units), normalise before hashing: decode, remove the BOM,
convert CRLF to LF, encode as UTF-8, then SHA-256. Exclude runtime-state files. For **integrity** of downloads,
binaries and signed artifacts, hash the **raw bytes** and never normalise.

**Why.** The same logical file has different hashes when one copy has CRLF or a BOM. That produces false "drift" alerts,
and people learn to ignore them. Runtime files (PID files, locks, caches, logs, `__pycache__`, generated timestamps)
change all the time and hide real drift.

**Wrong.**

```powershell
(Get-FileHash .\pve.conf).Hash -eq $linuxSha     # raw bytes: a CRLF checkout differs from the LF original
```

**Right.**

=== "Python"

    ```python
    import hashlib
    from pathlib import Path

    def normalized_sha256(path: Path) -> str:
        raw = path.read_bytes()
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            raw = raw.decode("utf-16").encode("utf-8")       # the utf-16 codec reads the BOM and drops it
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()

    IGNORE = ("*.pid", "*.lock", "*.log", "__pycache__/*", "*.pyc", ".cache/*")
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    function Get-NormalizedSha256 {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$LiteralPath)
        $full  = (Resolve-Path -LiteralPath $LiteralPath).ProviderPath
        $text  = [System.IO.File]::ReadAllText($full)          # detects a UTF-8/UTF-16 BOM, removes it
        $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes(($text -replace "`r`n", "`n"))
        $sha   = [System.Security.Cryptography.SHA256]::Create()
        try { -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    }
    ```

=== "Bash"

    ```bash
    normalized_sha256() {   # GNU sed; on macOS install gsed, or use the Python version
        sed '1s/^\xEF\xBB\xBF//' -- "$1" | sed 's/\r$//' | sha256sum | cut -d' ' -f1
    }
    find /etc/myapp -type f ! -name '*.pid' ! -name '*.lock' ! -path '*/cache/*' -print0 \
      | sort -z | while IFS= read -r -d '' f; do printf '%s  %s\n' "$(normalized_sha256 "$f")" "$f"; done
    ```

**How to test it.** Fixture test: one file saved as LF, CRLF, UTF-8 with a BOM and UTF-16LE must give **one**
normalised hash in all three implementations, and four different raw hashes. Keep the include and exclude globs in
the repository, next to the baseline manifest.

---

## 9. Data semantics in telemetry

**Rule.** Every number you emit or report states its **window** (lifetime, since boot, last N minutes), its **unit**,
the **time it describes** (not only the time it was sent) and its **quality**: `measured`, `estimated` or `snapshot`.

**Why.**

| Trap | Example | Consequence |
| :--- | :--- | :--- |
| Lifetime counter shown as a rate | `/proc/net/dev` bytes and Windows event totals count since boot | Charts jump or drop to zero after a reboot or counter wrap |
| Windowed value summed again | Adding up "per 5 min" averages | Wrong totals |
| Push time used as event time | Prometheus Pushgateway serves the last pushed value on every scrape; the scrape time looks fresh even after the pusher stopped | A dead job looks healthy. Alert on `push_time_seconds` instead |
| Unit mix-ups | Bits vs bytes (×8), KB vs KiB, ms vs s | Results are off by 8×, 1.024× or 1000× |
| Snapshot reported as a trend | One `df` reading in a report | Readers assume it is current |
| Estimate shown as a measurement | A projected backup size | Decisions based on numbers nobody measured |

**Wrong.**

```json
{"metric": "rx", "value": 98231123, "ts": "2026-10-12 14:00"}
```

**Right.**

```json
{"metric": "net_rx_bytes_total", "value": 98231123, "unit": "bytes", "kind": "counter", "window": "since_boot",
 "quality": "measured", "observed_at": "2026-10-12T20:00:00Z", "emitted_at": "2026-10-12T20:00:03Z",
 "host": "pve1", "source": "/proc/net/dev"}
```

=== "Python"

    ```python
    from datetime import datetime, timezone
    rec = {"metric": "backup_size_bytes", "value": size, "unit": "bytes", "window": "lifetime",
           "quality": "snapshot", "observed_at": observed.isoformat(),
           "emitted_at": datetime.now(timezone.utc).isoformat()}
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    [pscustomobject]@{ metric = 'disk_free_bytes'; value = $free; unit = 'bytes'; window = 'instant'
        quality = 'measured'; observed_at = [DateTimeOffset]::UtcNow.ToString('o') } | ConvertTo-Json -Compress
    ```

=== "Bash"

    ```bash
    printf '{"metric":"load1","value":%s,"unit":"ratio","window":"1m","quality":"measured","observed_at":"%s"}\n' \
      "$(cut -d' ' -f1 /proc/loadavg)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ```

**How to test it.** For each dashboard panel, write down which field holds the window and which holds the unit. Reboot
a lab host and check that counter panels handle the reset (`rate()` or `increase()`, not the raw value). Stop a
pushing job and confirm that an alert fires on staleness.

---

## 10. Time

**Rule.** Store and transmit times as **ISO 8601 with an explicit offset**, preferably UTC (`Z`). Show local time only
at the display layer. Never estimate or invent a timestamp: if it is unknown, record `null` and say why. Keep host
clocks synchronised and check skew before you correlate events across hosts.

**Why.**

- A naive time such as `2026-10-12 14:00` has no zone. The same string means different instants on hosts in
  different zones, and some local times happen twice or not at all when daylight saving time changes.
- Jobs scheduled in local time inside the DST change window can be skipped or run twice, depending on the scheduler.
- Clock skew breaks Kerberos (the default tolerance is 5 minutes), TLS validity checks, TOTP codes and log
  correlation.
- PowerShell 7 `ConvertFrom-Json` turns ISO 8601 strings into `[datetime]` objects (verified). Round trips can shift
  the time zone. Recent 7.x releases add `-DateKind` to control this.
- Python `datetime.utcnow()` returns a naive value and is deprecated since 3.12.

**Wrong.**

```python
ts = datetime.now().strftime("%Y-%m-%d %H:%M")        # local, no offset
ts = datetime.utcnow().isoformat()                    # naive: no 'Z' and no offset
```

```powershell
Get-Date -Format 'yyyy-MM-dd HH:mm'                   # local, no offset
```

**Right.**

=== "Python"

    ```python
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo                      # Windows: pip install tzdata
    now_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")          # 2026-10-12T20:00:00+00:00
    local   = datetime.now(ZoneInfo("America/Edmonton")).isoformat(timespec="seconds")   # ...-06:00
    parsed  = datetime.fromisoformat("2026-10-12T20:00:00Z")                    # 3.11+ accepts 'Z'
    assert parsed.tzinfo is not None
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    [DateTimeOffset]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")    # 2026-10-12T20:00:00Z
    [DateTimeOffset]::Now.ToString('o')                               # local time with offset
    [DateTimeOffset]::Parse('2026-10-12T20:00:00Z', [cultureinfo]::InvariantCulture)
    # 7.1+: Get-Date -AsUTC
    ```

=== "Bash"

    ```bash
    date -u +%Y-%m-%dT%H:%M:%SZ          # UTC
    date --iso-8601=seconds              # local time with offset (GNU); macOS: date +%Y-%m-%dT%H:%M:%S%z
    TZ=America/Edmonton date -d '2026-10-12T20:00:00Z'
    ```

**Clock checks.**

```bash
timedatectl status; chronyc tracking                 # Linux: is it synchronised, and what is the offset
```

```powershell
w32tm /query /status
w32tm /stripchart /computer:pve1 /samples:3 /dataonly    # offset to another host
```

**How to test it.** Put a fixture date on each side of a DST change into your parser tests. Assert that every
timestamp your code emits matches `Z$` or `[+-]\d{2}:\d{2}$`. Before you correlate logs from several hosts, record
each host's clock offset.

---

## 11. Numbers and locale

**Rule.** Machine-readable data uses the **invariant culture**: `.` for decimals, no thousands separators, ISO 8601
dates, and byte-order (ordinal) sorting where order matters for comparison. Apply locale formatting only for display.

**Why.** These were reproduced in PowerShell:

| Expression | Result | Reason |
| :--- | :--- | :--- |
| `[double]'1,5'` (5.1 and 7) | `15` | The cast uses the invariant culture, where `,` is a thousands separator |
| `(1.5).ToString()` under `de-DE` | `1,5` | `ToString()` and `-f` use the current culture |
| `[datetime]'03/04/2026'` under `de-DE` | March 4 | Casts are culture-invariant (US order) |
| `Get-Date -Date '03/04/2026'` under `de-DE` | April 3 | Cmdlet parameter binding uses the current culture |

Elsewhere: Python `float("1,5")` raises `ValueError`, while `locale.atof` follows the locale. Bash `printf '%.1f'`
follows `LC_NUMERIC`. `sort` and `ls` order follow `LC_COLLATE`. Excel in comma-decimal locales expects `;` as the CSV
separator.

**Wrong.**

```powershell
"$size" | Out-File size.txt                    # "1,5" on a de-DE host
[double](Get-Content size.txt)                 # 15
```

**Right.**

=== "Python"

    ```python
    value = float(text)                              # always '.' decimal; fails loudly on '1,5'
    out = f"{value:.3f}"                             # locale-independent ('n' format is locale-dependent)
    rows.sort(key=lambda r: r["name"])               # code-point order: stable across hosts
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    $inv = [cultureinfo]::InvariantCulture
    $value = [double]::Parse($text, $inv)
    $out = $value.ToString('0.###', $inv)
    $date = [datetime]::ParseExact('2026-10-12', 'yyyy-MM-dd', $inv)
    [string[]]$names = $list; [Array]::Sort($names, [StringComparer]::Ordinal)
    ```

=== "Bash"

    ```bash
    LC_ALL=C sort file                       # byte order, the same on every host
    LC_ALL=C printf '%.2f\n' "$value"        # '.' decimal regardless of the user's locale
    ```

**How to test it.** Run the parser tests once with a comma-decimal culture
(`[cultureinfo]::CurrentCulture = 'de-DE'` in PowerShell 7, `LC_ALL=de_DE.UTF-8` on Linux) and once with `en-US`.
The outputs must be identical.

---

## 12. JSON, YAML and CSV pitfalls

**Rule.** Serialise with a library, never with string templates. Quote YAML strings that could be read as another
type. Write CSV with the `csv` module or `Export-Csv`, never with `-join ','`. Send the correct `Content-Type` with a
charset. NDJSON is one object per line, LF, with a final newline.

**Why.**

| Format | Pitfall | Example |
| :--- | :--- | :--- |
| Any file read as a secret | A trailing newline becomes part of the value | `echo pw > f` then `kubectl create secret --from-file` stores `pw\n`. Bash `$(cat f)` strips trailing newlines; Python `read()` and `Get-Content -Raw` do not |
| YAML 1.1 (PyYAML) | Implicit typing | `no` → `False`, `0123` → `83` (octal), `12:30` → `750` (base 60), `1_000` → `1000`, `~` → `None`; `1e3` stays a string. Verified with PyYAML |
| YAML | Unsafe loaders | `yaml.load` without `SafeLoader` can build arbitrary objects |
| CSV | Formula injection | Cells that start with `=`, `+`, `-`, `@`, tab or CR are run as formulas by spreadsheet programs |
| CSV | Quoting and newlines | Fields with `,`, `"` or line breaks need quoting; Python needs `newline=""` |
| CSV (5.1) | `Export-Csv` adds a `#TYPE` line without `-NoTypeInformation`, and writes ASCII by default | — |
| JSON (5.1) | `ConvertTo-Json` default `-Depth 2` truncates nested objects **silently** to `"System.Collections.Hashtable"`. 7 prints a warning but still truncates. Verified | — |
| JSON | `ensure_ascii=True` (Python default) writes `\u00e9` | Valid JSON, but `grep` and humans do not find `é` |
| JSON | A BOM at the start | Python `json` rejects it (Section 4) |
| HTTP | Missing or wrong `Content-Type` | Recent Elasticsearch versions reject bodies without a supported `Content-Type`. Other services may parse the body as form data or plain text and still return 2xx |
| NDJSON | No final newline; a pretty-printed object across several lines | Elasticsearch `_bulk` requires the final newline; multi-line objects are not NDJSON |

**Wrong.**

```powershell
"{`"name`": `"$name`"}"                                          # breaks on a quote in $name
$obj | ConvertTo-Json | Invoke-RestMethod -Uri $u -Method Post   # depth 2; 5.1 may not send UTF-8; no Content-Type
```

```yaml
country: NO          # becomes false
mode: 0644           # becomes 420
version: 1.10        # becomes 1.1
```

**Right.**

=== "Python"

    ```python
    import csv, json
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8"}

    with open("out.ndjson", "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def csv_safe(cell: str) -> str:             # text columns only: it would also prefix negative numbers
        return "'" + cell if cell[:1] in ("=", "+", "-", "@", "\t", "\r") else cell

    with open("out.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerows([[csv_safe(str(c)) for c in row] for row in rows])

    import yaml
    data = yaml.safe_load(text)
    ```

=== "PowerShell 5.1 and 7"

    ```powershell
    $json  = $obj | ConvertTo-Json -Depth 20 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)              # explicit UTF-8 body for 5.1 and 7
    Invoke-RestMethod -Uri $u -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8'

    # NDJSON
    $lines = foreach ($r in $records) { $r | ConvertTo-Json -Depth 20 -Compress }
    [System.IO.File]::WriteAllText($path, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))

    # CSV. 5.1 needs both parameters, and UTF8 there includes a BOM (which Excel wants). 7: no BOM, no #TYPE line
    $rows | Export-Csv -LiteralPath out.csv -NoTypeInformation -Encoding UTF8
    ```

=== "Bash"

    ```bash
    jq -n --arg name "$name" '{name: $name}'                          # jq quotes and escapes the value
    jq -c '.[]' array.json > out.ndjson                               # one compact object per line, LF
    printf '%s' "$pw" > secret.txt                                    # no trailing newline
    kubectl create secret generic app --from-file=password=secret.txt
    ```

```yaml
country: "NO"
mode: "0644"
version: "1.10"
```

**How to test it.**

```bash
tail -c1 out.ndjson | od -An -c                           # must be \n
jq -c . out.ndjson > /dev/null                            # every line parses
python -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1], encoding='utf-8')))" config.yml   # see the real types
yamllint config.yml                                       # its 'truthy' rule flags yes/no/on/off
```

Add a round-trip test: serialise, parse back, and compare with the original object, including one nested level more
than you expect and one non-ASCII string.

---

## Pre-commit checklist

- [ ] `.gitattributes` exists, with `eol=lf` for `*.sh`, `*.py`, `*.service`, `*.conf` and `*.yml`. `git ls-files --eol` shows no `w/crlf` for those types.
- [ ] No file Linux executes or parses has a BOM or CRLF (`file`, `grep -c $'\r'`).
- [ ] Every `subprocess` call that sends data uses `input=<bytes>` and no `text=True`, or opens files with `newline="\n"`.
- [ ] Every `open()`, `read_text()` and `write_text()` names `encoding=`.
- [ ] PowerShell file writes name `-Encoding` (5.1: use `[IO.File]::WriteAllText` with `UTF8Encoding($false)` when no BOM is wanted).
- [ ] No secrets in argv, URLs, environment variables of long-lived processes, logs, history or exception messages.
- [ ] Secrets are validated: length, character set, no `\r`, `\n` or `\0`, no tool delimiters. Trimming removes only CR/LF at the ends.
- [ ] Every state change is followed by an effect check (login, read-back, query), not only an exit-code check.
- [ ] Credential changes: previous version kept, second access path proven, canary node first, fresh-login test.
- [ ] Remote scripts go over stdin (`bash -s`); arguments are quoted once with `shlex.join` or `printf %q`; heredocs are `<<'EOF'` unless expansion is intended.
- [ ] Paths are built with `pathlib`, `Join-Path` or `mktemp`. `-LiteralPath` is used for user-supplied names. No hard-coded `/tmp` or `$env:TEMP`.
- [ ] Drift hashes use the normalised hash; integrity hashes use raw bytes; runtime-state files are excluded.
- [ ] Telemetry records carry a unit, a window, a quality label and an observation time.
- [ ] Timestamps are ISO 8601 with an offset; no naive `datetime`; nothing estimated.
- [ ] Number and date parsing uses the invariant culture or a fixed format.
- [ ] JSON is built with a serializer (`-Depth` set in PowerShell). YAML strings that could change type are quoted, and code uses `safe_load`. CSV is written with `newline=""` and formula-safe cells. `Content-Type` includes the charset. NDJSON ends with LF.
- [ ] `set -euo pipefail` in Bash, `Set-StrictMode -Version 3.0` and `$ErrorActionPreference = 'Stop'` in PowerShell, and `$LASTEXITCODE` checked after native calls.

## Red flags in code review

| Red flag | Why it matters | Replace with |
| :--- | :--- | :--- |
| `subprocess.run(..., input=s, text=True)` running on Windows | `\n` becomes `\r\n` on the child's stdin | `input=s.encode("utf-8")` |
| `'...' \| native.exe` in PowerShell carrying data or secrets | Adds CRLF; 5.1 also uses ASCII | `Invoke-NativeStdinBytes`, `Start-Process -RedirectStandardInput` |
| A secret in argv: `sshpass -p`, `-p$pw`, `--password`, `curl -u user:pw` | Visible in `ps`, 4688, Sysmon and `CalledProcessError` | stdin, a file with mode 0600, a credential helper |
| `Out-File`, `>` or `Set-Content` without `-Encoding` (5.1) | UTF-16LE or ANSI output | Explicit encoding or `WriteAllText` |
| `-Encoding utf8` in code that runs on 5.1 | Writes a BOM | `UTF8Encoding($false)` |
| `open(p)` or `read_text()` without `encoding=` | Different behaviour on Windows and Linux | `encoding="utf-8"` |
| `.strip()` or `.Trim()` on a secret | Removes legitimate spaces | `.strip("\r\n")` and then reject control characters |
| `if rc == 0: print("done")` after a change | Exit code is not the effect | A read-back or login assertion |
| `usermod -p "$plain"` | Stores plain text as the hash | `chpasswd` (bytes on stdin) |
| `curl` without `--fail` or `--fail-with-body` in a script | HTTP errors exit 0 | `--fail-with-body` and a check of the body |
| A Bash pipeline without `pipefail` | Hides the failure of the first command | `set -euo pipefail` |
| `ssh host "... $var ..."` with nested quotes | Local expansion and re-parsing by the remote shell | `ssh host 'bash -s' < file`, `printf %q` |
| An unquoted heredoc sent to a remote host | Expands on the local machine | `<<'EOF'` |
| `ConvertTo-Json` without `-Depth` | Silent truncation (5.1) | `-Depth 20` (or the depth you actually need) |
| JSON or CSV built by string concatenation | Breaks on quotes and newlines; injection | A serializer, `csv` module, `jq --arg` |
| YAML `yes`/`no`/`on`/`off`, leading-zero numbers or versions without quotes | Type changes | Quote them; `yamllint` |
| `yaml.load(` without `SafeLoader` | Builds arbitrary objects | `yaml.safe_load` |
| `datetime.now()` / `utcnow()` in data; `Get-Date -Format` without an offset | Naive or ambiguous time | `datetime.now(timezone.utc)`, `[DateTimeOffset]::UtcNow` |
| `[double]$text`, `ToString()` or `-f` on machine data | Culture-dependent | Invariant culture or a fixed format |
| `Get-FileHash` compared across platforms for config drift | CRLF or BOM differences look like drift | Normalised hash |
| `-Path` with user-supplied names | `[` `]` treated as wildcards | `-LiteralPath` |
| Paths written as `"C:\\..." + name` or a literal `/tmp` | Not portable; path traversal | `pathlib`, `Join-Path`, `tempfile` |
| Secrets in a URL or query string | Logged by proxies and servers | A POST body or an `Authorization` header |
| `set -x`, `print(cmd)` or verbose HTTP logging around secret handling | The secret ends up in logs | Redact, or turn tracing off around that block |

## Related

- [Hash Functions](../concepts/hash-functions.md)
- [SSH Key Mechanics](../identity/ssh-keys.md)
- [Proxmox](../../platforms/virtualization/proxmox.md)
- [PowerShell fundamentals and pitfalls](../../languages/powershell/fundamentals.md)
