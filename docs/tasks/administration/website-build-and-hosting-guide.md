---
title: Administration — End-to-End Website Build & Hosting Guide
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-28
difficulty: intermediate
tags:
  - nginx
  - postgresql
  - dns
  - tls
  - certbot
  - caddy
  - vps
  - proxmox
  - static-site
  - reverse-proxy
---

# Administration — End-to-End Website Build & Hosting Guide

End-to-end reference for deploying a web application from local development to production — covering frontend build tooling, database setup, NGINX reverse proxy, DNS, TLS, and a comparison of hosting environments.

---

## 1. Frontend: Static vs Framework

### Static HTML/CSS/JS

No build step required; serve files directly from NGINX or a CDN.

```html
<!-- index.html — served as-is; no bundler needed -->
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>My Site</title></head>
  <body><h1>Hello</h1></body>
</html>
```

Best for: documentation sites, landing pages, simple tools with no dynamic state.

### React / Vue with Vite

```bash
# Scaffold a new project
npm create vite@latest my-app -- --template react
cd my-app && npm install

# Development server (hot-module reload)
npm run dev

# Production build → dist/
npm run build
```

The `dist/` directory contains static assets that NGINX can serve directly.  
Key `vite.config.js` options:

| Option | Purpose |
|--------|---------|
| `base: "/app/"` | Set if the site lives at a sub-path, not the root |
| `build.outDir` | Change output directory (default `dist`) |
| `server.proxy` | Proxy `/api/*` to a backend during development |

---

## 2. Database: PostgreSQL Setup

### Install and initialise

```bash
# Debian/Ubuntu
sudo apt install -y postgresql

# Rocky/RHEL/AlmaLinux
sudo dnf install -y postgresql-server
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

### Create a database and application user

```bash
sudo -u postgres psql <<'SQL'
CREATE DATABASE myapp;
CREATE USER myapp_user WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE myapp TO myapp_user;
-- Restrict to this DB only (principle of least privilege)
REVOKE CONNECT ON DATABASE myapp FROM PUBLIC;
GRANT CONNECT ON DATABASE myapp TO myapp_user;
SQL
```

### Basic hardening

```ini
# /etc/postgresql/<version>/main/postgresql.conf
listen_addresses = 'localhost'   # bind only to loopback unless remote access is required
ssl = on                         # enable TLS for any remote connections
```

```ini
# /etc/postgresql/<version>/main/pg_hba.conf
# Allow local socket connections only for the application user
local   myapp   myapp_user   scram-sha-256
# Reject everything else from network
host    all     all          0.0.0.0/0   reject
```

### Connection string

```
postgresql://myapp_user:changeme@127.0.0.1:5432/myapp?sslmode=require
```

Store the connection string in an environment variable, not in code:

```bash
export DATABASE_URL="postgresql://myapp_user:changeme@127.0.0.1:5432/myapp?sslmode=require"
```

---

## 3. NGINX: Reverse Proxy + TLS Terminator

### Install

```bash
sudo apt install -y nginx          # Debian/Ubuntu
sudo dnf install -y nginx          # RHEL-family
sudo systemctl enable --now nginx
```

### Serve a static Vite build

```nginx
# /etc/nginx/sites-available/myapp
server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/myapp/dist;
    index index.html;

    # Single-page app: fall back to index.html for client-side routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets aggressively
    location ~* \.(js|css|png|jpg|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Proxy to an application backend

```nginx
upstream app_backend {
    server 127.0.0.1:8000;     # gunicorn, node, go, etc.
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Proxy API requests to backend
    location /api/ {
        proxy_pass         http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
    }

    # Static frontend
    location / {
        root /var/www/myapp/dist;
        try_files $uri $uri/ /index.html;
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

### Recommended security headers

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

---

## 4. DNS: Records, Delegation, Split-Horizon

### Common record types

| Type | Purpose | Example value |
|------|---------|---------------|
| `A` | Maps hostname → IPv4 | `93.184.216.34` |
| `AAAA` | Maps hostname → IPv6 | `2606:2800:…` |
| `CNAME` | Alias to another hostname | `www → example.com.` |
| `MX` | Mail exchanger | `10 mail.example.com.` |
| `TXT` | Free text (SPF, DKIM, verification) | `v=spf1 include:… -all` |
| `NS` | Authoritative nameservers | `ns1.registrar.com.` |
| `SOA` | Zone metadata | (managed by registrar) |

### TTL guidance

| Scenario | Recommended TTL |
|----------|----------------|
| Stable production record | 3600 s (1 h) or 86400 s |
| Before a planned migration | 300 s (5 min), 24 h beforehand |
| CDN or load-balanced target | 60–300 s |

### Domain registrar → nameserver delegation

```
Registrar control panel:
  Nameservers → Custom
    ns1.yourdns.com
    ns2.yourdns.com
```

The registrar publishes NS records at the TLD (`.com`, `.net`) level.  
Your nameserver (Cloudflare, Route 53, self-hosted BIND/PowerDNS) then answers queries for your zone.

### Split-horizon DNS for homelab

Run an internal resolver (Unbound, Pi-hole, CoreDNS) that returns private IPs for your services while the public DNS resolves to a public IP or returns NXDOMAIN.

```conf
# Unbound: override example.com for LAN clients
local-zone: "example.com." static
local-data: "example.com. A 192.168.10.20"
local-data: "www.example.com. CNAME example.com."
```

Clients on the LAN use `192.168.10.20` (direct); external clients use the public IP (via NGINX or the reverse proxy).

---

## 5. TLS/HTTPS

### Option A — Let's Encrypt with Certbot (NGINX plugin)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d example.com -d www.example.com
```

Certbot modifies the NGINX config automatically, inserts the certificate paths, and creates a systemd timer for renewal.

```bash
# Test renewal without overwriting certs
sudo certbot renew --dry-run

# Verify the timer is active
systemctl status certbot.timer
```

Certificates are stored under `/etc/letsencrypt/live/<domain>/` and expire after 90 days; the timer renews at 60 days.

### Option B — Caddy (automatic HTTPS)

Caddy requests and renews Let's Encrypt certificates automatically; no manual Certbot step is needed.

```caddyfile
# /etc/caddy/Caddyfile
example.com {
    # Serve static files
    root * /var/www/myapp/dist
    file_server

    # Proxy /api to backend
    reverse_proxy /api/* localhost:8000
}
```

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
sudo systemctl enable --now caddy
```

Caddy handles HTTP-01 or TLS-ALPN-01 challenges and stores certificates in `/var/lib/caddy/.local/share/caddy`.

### Wildcard certificates (DNS-01 challenge)

Required when you need `*.example.com`. Use the Certbot DNS plugin for your registrar:

```bash
sudo apt install -y python3-certbot-dns-cloudflare
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d "*.example.com" -d "example.com"
```

---

## 6. Hosting Environment Comparison

| Factor | Homelab (Proxmox VM/LXC) | VPS (DigitalOcean / Linode / Hetzner) | Shared hosting |
|--------|--------------------------|--------------------------------------|---------------|
| Cost | Hardware amortised; power bill | $4–$20 /mo (1–2 vCPU, 1–4 GB) | $3–$10 /mo |
| Control | Full root on bare metal | Full root | cPanel only |
| Uptime | Depends on your hardware/UPS | 99.9% SLA typical | 99.9% SLA |
| IP reputation | Residential/ISP — may be blocked by port 25 relays | Clean datacenter IP | Shared IP pool |
| Scalability | Manual (new VM/LXC) | Resize/snapshot in seconds | Limited |
| Learning value | High (DNS, routing, BGP, DHCP all yours) | Medium | Low |
| Best for | Local dev, private services, cost-zero if hardware already owned | Production public sites | Simple blogs, small stores |

### Proxmox — quick VM/LXC deployment

```bash
# Create an LXC container from the Debian 12 template
pct create 200 local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst \
  --hostname webserver \
  --memory 1024 \
  --cores 2 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.10.20/24,gw=192.168.10.1 \
  --storage local-lvm \
  --rootfs local-lvm:10 \
  --unprivileged 1
pct start 200
```

### VPS provider — initial hardening checklist

After first login as root:

```bash
# Create a non-root admin user
adduser deploy
usermod -aG sudo deploy

# Copy your SSH public key
mkdir -p /home/deploy/.ssh
echo "<your-pubkey>" > /home/deploy/.ssh/authorized_keys
chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh

# Harden SSH
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Enable UFW
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw enable
```

---

## 7. End-to-End Deployment Checklist

```
[ ] Frontend built (npm run build) and dist/ copied to /var/www/<app>/dist
[ ] PostgreSQL: DB + user created; listen_addresses = 'localhost'; pg_hba.conf tightened
[ ] NGINX config: sites-available created and linked; nginx -t passes; reload issued
[ ] DNS: A record for domain points to server IP; TTL appropriate; propagation verified
[ ] TLS: Certbot (or Caddy) issued cert; HTTPS works; HTTP redirects to HTTPS
[ ] Security headers set in NGINX (HSTS, X-Frame-Options, CSP, etc.)
[ ] Firewall: only ports 22, 80, 443 open (ufw status)
[ ] Database connection string in environment variable, not in code
[ ] Certbot renewal timer active (systemctl status certbot.timer)
[ ] Split-horizon DNS configured if homelab internal access needed
```

## See also

- [Deploy TLS Certificates & Harden Web Servers](tls-certificate-deployment.md)
- [Deploy a WireGuard VPN Gateway](wireguard-vpn-deployment.md)
- [Manage Host Firewall & Ports](firewall-port-management.md)
- [Deploy SPF, DKIM & DMARC](email-authentication-deployment.md)
