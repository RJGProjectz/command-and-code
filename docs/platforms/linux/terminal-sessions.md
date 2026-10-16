---
title: Linux Terminal Sessions — screen, tmux & Background Jobs
platforms: [Linux]
languages: [Bash]
tasks: [Administration, Troubleshooting, Investigation, Incident Response]
category: Remote Access
tags: [tmux, screen, nohup, disown, setsid, systemd-run, loginctl, linger, ssh, background jobs]
aliases: [keep command running after ssh disconnect, detach session, reattach tmux, screen -r, tmux attach, run in background linux, nohup, persistent shell]
difficulty: basic
verified: true
last_verified: 2026-10-16
---

# Linux Terminal Sessions — screen, tmux & Background Jobs

When an SSH connection drops, the shell receives `SIGHUP` and every job started from it normally dies with it. Long tasks (patching, large copies, imaging a disk, a forensic collection) need to survive that. Linux offers three families of tools:

| Need | Use | Survives SSH drop | Can reattach to the screen |
| :--- | :--- | :---: | :---: |
| Interactive work you come back to | **tmux** or **screen** (terminal multiplexers) | Yes | Yes |
| Fire-and-forget command, output to a file | `nohup`, `setsid`, `disown` | Yes | No (read the log) |
| Managed background job with logs, limits and status | `systemd-run` (transient unit) | Yes | No (use `journalctl`) |
| Job that must survive **logout** on systemd hosts | `systemd-run --user` + `loginctl enable-linger`, or a system unit | Yes | No |

!!! tip "Which one?"
    Use **tmux** for interactive admin work, **systemd-run** for anything that should run unattended and be auditable. `nohup` is the quick fallback that works everywhere.

## 1. tmux

tmux runs a per-user server; sessions keep running after the client detaches. Default prefix key: **`Ctrl-b`**.

### Start, detach, reattach

```bash
tmux new-session -s patching          # new named session (attached)
tmux new-session -d -s copy 'rsync -a /data/ /backup/data/'   # start detached, running a command
# inside tmux: Ctrl-b d  → detach
tmux list-sessions                    # or: tmux ls
tmux attach-session -t patching       # or: tmux a -t patching
tmux kill-session -t copy
```

### Everyday keys (after `Ctrl-b`)

| Key | Action |
| :--- | :--- |
| `d` | Detach the client |
| `c` / `n` / `p` | New window / next / previous |
| `%` / `"` | Split pane left-right / top-bottom |
| arrow keys | Move between panes |
| `[` | Scroll/copy mode (`q` to leave) |
| `s` | Choose a session from a list |
| `?` | List all key bindings |

### Capture what is on screen (evidence, tickets)

```bash
# Print the pane plus 3000 lines of history to a file
tmux capture-pane -p -S -3000 -t patching > ~/patching-$(date -u +%Y%m%dT%H%M%SZ).txt

# Log everything a pane prints from now on
tmux pipe-pane -o -t patching 'cat >> ~/patching.log'
```

### Sockets and sharing

- The server socket lives under `$TMUX_TMPDIR` (default `/tmp`) in a per-user `tmux-<UID>/` directory; the default socket is named `default`.
- `-L name` starts a separate server with a different socket name; `-S /path` uses a full socket path.
- By default only the owner (and root) can connect. tmux 3.3+ can grant other users access with `server-access -a <user>`; add `-r` for **read-only** viewers. Prefer read-only when pairing on production.

## 2. GNU screen

Older but installed almost everywhere (including many appliances). Default prefix key: **`Ctrl-a`**.

```bash
screen -S patching                    # new named session
screen -d -m -S copy rsync -a /data/ /backup/data/   # start detached
# inside screen: Ctrl-a d  → detach
screen -ls                            # list sessions (pid.name)
screen -r patching                    # reattach a detached session
screen -x patching                    # attach to a session that is still attached elsewhere (shared view)
screen -S copy -X quit                # send a command to a session (here: end it)
screen -L -S build                    # log window output (default file: screenlog.0)
```

- Socket directory depends on how screen was built (commonly `/run/screen/S-<user>/`, older builds `/tmp/screens` or `~/.screen`). If screen is not setuid-root, `$SCREENDIR` can point at a mode-700 directory.
- **Multiuser mode** (`multiuser on`, `acladd <user>`) lets another user attach with `screen -r owner/session`, which requires screen to be **setuid-root**. Treat a setuid-root screen as a privilege-escalation surface; most distributions no longer ship it that way.

### screen ↔ tmux quick map

| Task | screen | tmux |
| :--- | :--- | :--- |
| New named session | `screen -S x` | `tmux new -s x` |
| Detach | `Ctrl-a d` | `Ctrl-b d` |
| List | `screen -ls` | `tmux ls` |
| Reattach | `screen -r x` | `tmux a -t x` |
| Shared attach | `screen -x x` | `tmux a -t x` (second client) |
| Kill | `screen -S x -X quit` | `tmux kill-session -t x` |

## 3. nohup, disown, setsid (no multiplexer)

```bash
# Ignore SIGHUP; stdout/stderr go to the file you name (else ./nohup.out)
nohup ./long-job.sh > ~/long-job.log 2>&1 &

# Already started in the foreground? Suspend, background, detach from the shell's job table
#   Ctrl-z
bg
disown -h %1          # bash: do not send SIGHUP to job 1 when the shell exits

# Start in a brand-new session with no controlling terminal
setsid -f ./long-job.sh > ~/long-job.log 2>&1 < /dev/null
```

None of these lets you see the terminal again; always redirect output to a log.

## 4. systemd-run and lingering (systemd hosts)

### Transient unit — the auditable way

```bash
# System-wide (root): runs as a service with its own journal and resource accounting
sudo systemd-run --unit=reindex --description="Reindex archive" --collect \
  /usr/local/bin/reindex.sh
systemctl status reindex.service
journalctl -u reindex.service -f

# Per-user, no root needed
systemd-run --user --unit=longjob --collect ./long-job.sh
journalctl --user -u longjob.service -f
```

`--collect` unloads the unit when it ends, even if it failed; without it a failed unit stays until `systemctl reset-failed`. `--scope` instead runs the command in the foreground as a `.scope` unit (useful only for grouping and limits).

### Why jobs still die at logout: `KillUserProcesses`

`systemd-logind` can kill every process in a user's session when the user logs out — **including tmux and screen servers**. The `logind.conf(5)` man page documents the default as `yes`; many distributions ship `no`. Check the effective value:

```bash
systemd-analyze cat-config systemd/logind.conf | grep -i -E 'KillUserProcesses|KillExcludeUsers|KillOnlyUsers'
loginctl show-user "$USER" -p Linger
```

Options when sessions are being killed:

```bash
# 1. Allow the user's service manager to run without a login session
sudo loginctl enable-linger <user>
systemd-run --user --unit=work tmux new-session -d -s work    # tmux server outside the login scope

# 2. Or run tmux in its own scope from an interactive shell
systemd-run --user --scope tmux new-session -s work
```

Lingering is a standing change: record it, and remove it with `loginctl disable-linger <user>` when the work is done.

## 5. Related tools

| Tool | What it adds |
| :--- | :--- |
| **byobu** | Friendly front end with status bar on top of tmux or screen |
| **zellij** | Newer multiplexer with on-screen key hints and layouts |
| **mosh** | Roaming UDP-based SSH replacement for flaky links (no scrollback; pair with tmux) |
| **abduco / dtach** | Detach/reattach only, no windows or panes |
| **at / batch** | Queue a one-off job for later (see [Cron & timers](cron.md)) |

## 6. Security & investigation

Multiplexer sessions are long-lived shells. For defenders they matter in two ways: they keep an interactive foothold alive after the attacker's SSH session closes ([T1059.004](https://attack.mitre.org/techniques/T1059/004/)), and their sockets let anyone with access to the socket type into the shell.

### Find sessions on a host

```bash
# Running servers and clients
ps -eo pid,ppid,user,lstart,cmd | grep -E '[t]mux|[S]CREEN|[s]creen|[n]ohup|[s]etsid'

# Socket files (owner, age)
sudo find /tmp /run/screen /var/run/screen -maxdepth 2 \
  \( -path '*/tmux-*' -o -path '*/S-*' \) -ls 2>/dev/null

# Every user's tmux sessions (as root; reads each user's default socket)
for s in /tmp/tmux-*/default; do echo "== $s"; sudo tmux -S "$s" list-sessions 2>/dev/null; done

# Transient units and lingering users
systemctl list-units 'run-*' --all --no-pager
ls /var/lib/systemd/linger/ 2>/dev/null
```

!!! warning "Evidence first"
    Attaching to a suspect session as root changes it (window size, client list, possibly key input). Prefer `tmux -S <socket> capture-pane -p -S - -t <session>` to read the scrollback without attaching, and copy the output to your evidence folder before you kill anything.

**What to look for:** sessions owned by service accounts (`www-data`, `postgres`), sockets in unusual paths (`-S /dev/shm/...`), tmux servers whose parent is a web server or cron, `server-access` grants or screen `multiuser on` in `~/.tmux.conf` / `~/.screenrc`, lingering enabled for accounts that never log in interactively.

### Hardening

- Keep tmux/screen sockets in default per-user directories (mode 700); never chmod a socket to be world-writable for "sharing".
- Use read-only `server-access -r` for shadowing; avoid setuid-root screen.
- `TMOUT` in `/etc/profile.d/` ends idle shells but **not** detached multiplexer sessions; set `lock-after-time` (tmux) or `idle`/`lockscreen` (screen) if policy needs it.
- Leave `KillUserProcesses` and lingering as policy decisions: enabling either changes what survives logout.

## Related

- [Processes](processes.md)
- [Services (systemd)](systemd.md)
- [SSH](ssh.md)
- [Cron & timers](cron.md)
- Concept: [Processes and threads](../../fundamentals/concepts/processes-threads.md)
- Concept: [Services and daemons](../../fundamentals/concepts/services-daemons.md)

## Sources

- [tmux(1)](https://man7.org/linux/man-pages/man1/tmux.1.html)
- [screen(1)](https://man7.org/linux/man-pages/man1/screen.1.html)
- [nohup(1)](https://man7.org/linux/man-pages/man1/nohup.1.html)
- [setsid(1)](https://man7.org/linux/man-pages/man1/setsid.1.html)
- [bash(1) — disown](https://man7.org/linux/man-pages/man1/bash.1.html)
- [systemd-run(1)](https://man7.org/linux/man-pages/man1/systemd-run.1.html)
- [logind.conf(5)](https://man7.org/linux/man-pages/man5/logind.conf.5.html)
- [loginctl(1)](https://man7.org/linux/man-pages/man1/loginctl.1.html)
- [MITRE ATT&CK T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
