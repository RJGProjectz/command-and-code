---
title: Administration — SSH Tunneling & Port Forwarding
type: workflow
platforms:
  - Linux
  - Windows
languages:
  - Bash
tasks:
  - Administration
verified: false
difficulty: intermediate
tags:
  - ssh
  - tunnel
  - port-forwarding
  - local-forward
  - remote-forward
  - socks
  - dynamic-forwarding
  - proxyjump
  - jump-host
  - bastion
---

# Administration — SSH Tunneling & Port Forwarding

Securely reach services behind firewalls, route traffic through bastion hosts, and expose local listeners on remote systems using OpenSSH's built-in tunneling primitives.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against OpenSSH's documented syntax but have not been lab-run for this page.
    Confirm flags against `ssh(1)` / `ssh_config(5)` man pages in your build.
    Remove this block when `verified: true`.

---

## 1. Local Port Forwarding (-L)

Bind a port on your local machine and forward connections through the SSH tunnel to a destination reachable from the **remote** host. The destination is resolved from the server side — not your local machine.

```
ssh -L [local_addr:]<local_port>:<dest_host>:<dest_port> [user@]<ssh_server>
```

Common uses: reach a database, internal web dashboard, or service that is only accessible from the server's network.

```bash
# Forward localhost:5432 to a PostgreSQL host reachable from the bastion
ssh -L 5432:db.internal:5432 admin@bastion.example.com

# Forward local port 8080 to a web UI running on the SSH server itself
ssh -L 8080:localhost:80 admin@server.example.com

# Background / no-interactive-shell variant (-N = no command, -f = fork to background)
ssh -fN -L 5432:db.internal:5432 admin@bastion.example.com
```

Connect your local client to `localhost:<local_port>` once the tunnel is open.

---

## 2. Remote Port Forwarding (-R)

Bind a port on the **remote** server and forward incoming connections back through the tunnel to a destination reachable from your local machine.

```
ssh -R [remote_addr:]<remote_port>:<dest_host>:<dest_port> [user@]<ssh_server>
```

Common uses: expose a local dev server, webhook endpoint, or management interface on a remote host without opening inbound firewall rules locally. Binding on all interfaces on the remote side requires `GatewayPorts yes` in the server's `sshd_config`.

```bash
# Expose local port 3000 as port 8080 on the remote server (localhost-only by default)
ssh -R 8080:localhost:3000 admin@server.example.com

# Background / no-shell
ssh -fN -R 8080:localhost:3000 admin@server.example.com

# Bind on all remote interfaces (requires GatewayPorts yes on the server)
ssh -R 0.0.0.0:8080:localhost:3000 admin@server.example.com
```

---

## 3. Dynamic SOCKS5 Proxy (-D)

Create a SOCKS5 proxy on a local port. Applications that support SOCKS5 route their traffic through the SSH connection, with the remote host acting as the exit node.

```
ssh -D [bind_addr:]<local_socks_port> [user@]<ssh_server>
```

Common uses: proxy a browser or command-line tool through an SSH-connected host to access a private network or use the remote host's outbound IP.

```bash
# Start a SOCKS5 proxy on localhost:1080
ssh -D 1080 admin@bastion.example.com

# Background / no-shell
ssh -fN -D 1080 admin@bastion.example.com
```

Pass the proxy to `curl` or other tools:

```bash
# Route curl through the SOCKS5 proxy — DNS resolves on the remote side
curl --socks5-hostname 127.0.0.1:1080 http://internal.service/

# Use with ssh itself to chain into a further-internal host
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' admin@10.0.1.50
```

---

## 4. ProxyJump / Jump Hosts (-J)

Connect through one or more intermediate SSH hosts to a final destination. The jump host(s) relay only the encrypted SSH stream — they cannot see the inner session content.

```
ssh -J [user@]<jump1>[:<port>][,[user@]<jump2>,...] [user@]<target>
```

Common uses: reach a host in a private subnet via a public-facing bastion without copying private keys to the bastion.

```bash
# Single jump host
ssh -J admin@bastion.example.com admin@10.0.1.50

# Chained jump hosts (comma-separated, evaluated left to right)
ssh -J jump1.example.com,jump2.internal admin@10.0.0.10

# ProxyJump combined with local port forwarding through the chain
ssh -J admin@bastion.example.com -L 5432:db.internal:5432 -fN admin@10.0.1.50
```

---

## 5. ~/.ssh/config Persistent Patterns

Encode tunnels and jump routes as named aliases so they work with a single `ssh <Host>` command and are transparently used by `scp`, `rsync`, and other SSH-aware tools.

```text
# ~/.ssh/config

# Public-facing bastion definition
Host bastion
    HostName bastion.example.com
    User admin
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 60
    ServerAliveCountMax 3

# Private subnet host reached via bastion (ProxyJump)
Host db-server
    HostName 10.0.1.50
    User admin
    ProxyJump bastion
    IdentityFile ~/.ssh/id_ed25519

# Persistent local port-forward tunnel (invoke with: ssh -fN db-tunnel)
Host db-tunnel
    HostName bastion.example.com
    User admin
    LocalForward 5432 db.internal:5432
    ExitOnForwardFailure yes
    ServerAliveInterval 60
    ServerAliveCountMax 3

# Persistent SOCKS proxy (invoke with: ssh -fN socks-proxy)
Host socks-proxy
    HostName bastion.example.com
    User admin
    DynamicForward 1080
    ExitOnForwardFailure yes
    ServerAliveInterval 60
```

Start a named tunnel and verify the local port:

```bash
# Start the tunnel in the background
ssh -fN db-tunnel

# Confirm the port is open
ss -tlnp | grep 5432
```

Kill a background tunnel by PID:

```bash
# Find the tunnel process
pgrep -a ssh | grep db-tunnel

# Terminate it
kill <PID>
```

---

## 6. Tunnel Hygiene & Security

| Practice | Reason |
| :--- | :--- |
| Use `-fN` for background tunnels | Avoids leaving an open interactive shell on the intermediary |
| Set `ExitOnForwardFailure yes` | Kills the client if the port bind fails; prevents silent no-ops |
| Prefer `ProxyJump` over `ProxyCommand` | Simpler syntax and eliminates shell-injection risk from shared configs |
| Do not copy private keys to jump hosts | Agent forwarding (`ForwardAgent yes`) can be abused if the bastion is compromised — use `ProxyJump` instead |
| Keep `GatewayPorts no` (server default) | Prevents remote-forwarded ports from binding on non-localhost interfaces unless explicitly needed |
| Audit live tunnels regularly | `sudo ss -tlnp \| grep ssh` shows bound forward ports; `sudo ss -tnp state established` shows active sessions |

---

## Related

- [Administration — SSH Key Generation, Deployment & Best Practices](ssh-key-deployment.md)
- [Administration — Run an SSH Certificate Authority](ssh-certificate-authority.md)
- [Administration — Transfer Files Remotely (SCP/rsync)](remote-file-transfer.md)
- [Administration — Deploy a WireGuard VPN Gateway](wireguard-vpn-deployment.md)
- [Platforms — Linux SSH](../../platforms/linux/ssh.md)
- [Troubleshooting — SSH Connection Timeouts & Session Freezes](../../tasks/troubleshooting/ssh-connection-timeout-troubleshooting.md)

## Sources

- [ssh(1)](https://man.openbsd.org/ssh)
- [ssh_config(5)](https://man.openbsd.org/ssh_config)
- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
