---
title: Fundamentals — SSH Key Architecture & Cryptographic Baselines
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - ssh
  - ssh-keys
  - ed25519
  - cryptography
---

# Fundamentals — SSH Key Architecture & Cryptographic Baselines

Secure Shell (SSH) asymmetric key pairs eliminate password-based brute force and credential-stuffing attacks across Linux and Unix infrastructure.

## 1. Asymmetric Cryptography Key Algorithms

| Algorithm | Key Size | Security Stance | Recommendation |
| :--- | :--- | :--- | :--- |
| **Ed25519** | 256 bits | Fast, immune to side-channel timing attacks | **Primary Standard (Modern)** |
| **RSA** | 3072 / 4096 bits | High compatibility, slower generation | Acceptable (minimum 3072 bits) |
| **DSA / ECDSA** | Variable | Deprecated / potential curve implementation flaws | **Disallowed** |

---

## 2. Generation & Best Practice

```bash
# Generate modern Ed25519 key with custom comment and passphrase
ssh-keygen -t ed25519 -C "admin@example.com" -f ~/.ssh/id_ed25519_production

# Copy public key to remote host securely
ssh-copy-id -i ~/.ssh/id_ed25519_production.pub user@server.example.com
```

### Permissions Requirements
- Private key (`~/.ssh/id_ed25519`): `chmod 600` (Read/Write owner only)
- Public key (`~/.ssh/id_ed25519.pub`): `chmod 644`
- Authorized keys (`~/.ssh/authorized_keys`): `chmod 600`
- SSH directory (`~/.ssh`): `chmod 700`
