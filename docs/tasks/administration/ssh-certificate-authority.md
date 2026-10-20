---
title: Run an SSH Certificate Authority (User and Host Certificates)
type: workflow
platforms: [Linux, Windows, Windows Server]
languages: [Bash, PowerShell]
tasks: [Administration, Hardening]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [ssh, openssh, certificates, ssh-ca, krl, revocation, principals, known-hosts]
aliases: [ssh certificate authority, ssh-keygen -s, ssh user certificate, ssh host certificate, TrustedUserCAKeys, AuthorizedPrincipalsFile, AuthorizedPrincipalsCommand, cert-authority known_hosts, HostCertificate, RevokedKeys, key revocation list, ssh krl, ssh-keygen -k, short lived ssh certificates, replace authorized_keys, ssh certificate principals, ssh-keygen -L]
difficulty: advanced
verified: true
last_verified: 2026-10-20
---

# Run an SSH Certificate Authority (User and Host Certificates)
> **Created**: 2026-10-20T17:45:00Z
> **Last Modified**: 2026-10-20T17:45:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> The user CA private key can log in as anyone it lists as a principal on every server that trusts it.
> Keep it offline or in a hardware token, never on a server. A `RevokedKeys` file that sshd cannot read
> refuses public key logons for **all** users; test with `sshd -t` and keep a session open.

**Trigger:** `authorized_keys` files on many servers are out of date, leavers' keys stay valid for
years, and users click "yes" on unknown host key prompts.

**Goal:** servers trust one user CA instead of per-user keys, user certificates expire in hours or days,
clients trust one host CA instead of TOFU prompts, and a revoked key or certificate is refused everywhere.

| Piece | Where | Directive |
| :--- | :--- | :--- |
| User CA public key | every server | `TrustedUserCAKeys` |
| Allowed principals per account | every server | `AuthorizedPrincipalsFile` |
| Host certificate | every server | `HostCertificate` |
| Host CA public key | every client | `@cert-authority` in `known_hosts` |
| Revocation list (KRL) | servers / clients | `RevokedKeys` / `RevokedHostKeys` |

Plain key deployment, permissions and `ssh-agent` are covered in [Deploy SSH keys](ssh-key-deployment.md).

## 1. Create two CAs (user and host)

Use separate keys so a leak of one does not let the attacker do both jobs.

```bash
# On an offline or tightly controlled signing host
install -d -m 700 /srv/ssh-ca
ssh-keygen -t ed25519 -f /srv/ssh-ca/user_ca -C 'user-ca@example.com'    # set a strong passphrase
ssh-keygen -t ed25519 -f /srv/ssh-ca/host_ca -C 'host-ca@example.com'
chmod 600 /srv/ssh-ca/user_ca /srv/ssh-ca/host_ca
```

- `ssh-keygen -s` can also use a CA key held in `ssh-agent` (`-U`) or on a PKCS#11 token (`-D`), so the
  private key never sits in a file.
- Keep a serial counter (a file or the CA tool's database). Serials make revocation by range possible.

## 2. Sign user certificates

```bash
# Alice's own key pair stays on her device; only id_ed25519.pub is sent to the CA
ssh-keygen -s /srv/ssh-ca/user_ca \
    -I 'alice@example.com ticket-4711' \
    -n alice,web-admins \
    -V +8h \
    -z 1042 \
    -O clear -O permit-pty \
    alice_id_ed25519.pub                       # writes alice_id_ed25519-cert.pub

ssh-keygen -L -f alice_id_ed25519-cert.pub     # type, key ID, serial, principals, validity, options
```

| Option | Meaning (ssh-keygen(1)) |
| :--- | :--- |
| `-I` | Key ID, logged by sshd on every logon and usable for revocation; put the person and the reason in it |
| `-n` | Principals the certificate is valid for. A certificate with no principals is refused by `TrustedUserCAKeys` |
| `-V` | Validity, e.g. `+8h`, `-5m:+1d`, `20261101:20261201`. Avoid `forever` for users |
| `-z` | Serial number (`+N` auto-increments when signing several keys) |
| `-O clear` then `permit-*` | Start with no permissions and add only what is needed |
| `-O force-command=...`, `-O source-address=10.0.0.0/8` | Pin automation certificates to one command and source network |

Automation example (backup job, one command, one source network, 30 days):

```bash
ssh-keygen -s /srv/ssh-ca/user_ca -I 'svc-backup nightly' -n svc-backup -V +30d -z 2001 \
    -O clear -O force-command='/usr/local/bin/backup-receive' -O source-address=10.20.0.0/24 \
    svc_backup.pub
```

## 3. Configure servers to trust the user CA

```bash
install -m 644 user_ca.pub /etc/ssh/user_ca.pub
install -d -m 755 /etc/ssh/auth_principals
printf 'web-admins\n' > /etc/ssh/auth_principals/deploy     # account "deploy" accepts principal web-admins
printf 'alice\n'      > /etc/ssh/auth_principals/alice
chmod 644 /etc/ssh/auth_principals/*

cat > /etc/ssh/sshd_config.d/40-ssh-ca.conf <<'EOF'
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
RevokedKeys /etc/ssh/revoked_keys.krl
EOF

ssh-keygen -k -f /etc/ssh/revoked_keys.krl     # start with an empty KRL so the file exists and is readable
sshd -t && systemctl reload sshd               # 'ssh' on Ubuntu
```

- Without `AuthorizedPrincipalsFile`, the **user name** must appear in the certificate's principals.
  With it, the principals listed in the file for that account decide, so one certificate principal
  (`web-admins`) can map to a shared account without sharing a key.
- `AuthorizedPrincipalsCommand` (Linux only) can look principals up from a directory instead of files.
- Leave `AuthorizedKeysFile` in place during migration; remove user keys once every user has a
  certificate.

Windows OpenSSH Server reads `%ProgramData%\ssh\sshd_config` and supports `TrustedUserCAKeys`,
`AuthorizedPrincipalsFile` and `RevokedKeys`, but not `AuthorizedPrincipalsCommand`:

```powershell
Copy-Item .\user_ca.pub "$Env:ProgramData\ssh\user_ca.pub"
Add-Content "$Env:ProgramData\ssh\sshd_config" @'
TrustedUserCAKeys __PROGRAMDATA__/ssh/user_ca.pub
RevokedKeys __PROGRAMDATA__/ssh/revoked_keys.krl
'@
& "$Env:SystemRoot\System32\OpenSSH\ssh-keygen.exe" -k -f "$Env:ProgramData\ssh\revoked_keys.krl"
& "$Env:SystemRoot\System32\OpenSSH\sshd.exe" -t
Restart-Service sshd
```

Put the lines above any `Match` block in the file; settings after `Match` apply only to that match.

## 4. Host certificates: no more trust-on-first-use

```bash
# Sign the server's existing host key (run on the CA, with the copied ssh_host_ed25519_key.pub)
ssh-keygen -s /srv/ssh-ca/host_ca -h \
    -I 'web01 host key' -n web01,web01.example.com,10.20.1.15 -V +52w -z 9001 \
    ssh_host_ed25519_key.pub

# On the server: install the certificate next to its key
install -m 644 ssh_host_ed25519_key-cert.pub /etc/ssh/
echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' > /etc/ssh/sshd_config.d/41-host-cert.conf
sshd -t && systemctl reload sshd
```

On clients (or in `/etc/ssh/ssh_known_hosts` for all users):

```text
@cert-authority *.example.com,10.20.* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... host-ca@example.com
```

- The certificate's public key must match a `HostKey` already loaded by sshd.
- The names in `-n` must cover every name clients use (short name, FQDN, IP), or clients fall back to
  the plain key prompt.
- Rotate host certificates before `-V` runs out; an expired host certificate brings the prompt back.

## 5. Revoke keys and certificates (KRL)

```bash
cat > revoke.spec <<'EOF'
serial: 1042
id: alice@example.com ticket-4711
serial: 1100-1199
EOF
ssh-keygen -k -u -s /srv/ssh-ca/user_ca.pub -f revoked_keys.krl revoke.spec   # -u adds to the existing KRL
ssh-keygen -k -u -f revoked_keys.krl lost_laptop_id_ed25519.pub                 # revoke a plain key
ssh-keygen -Q -f revoked_keys.krl alice_id_ed25519-cert.pub                     # non-zero exit = revoked
```

- Copy the KRL to every server (`/etc/ssh/revoked_keys.krl`, mode 644) with your config tool.
  sshd reads it on every logon, so no reload is needed.
- An unreadable `RevokedKeys` file blocks all public key logons. Deploy with an atomic rename and check
  the mode afterwards.
- For host keys, clients use `RevokedHostKeys` in `ssh_config`, or `@revoked` lines in `known_hosts`.
- Short validity (`-V +8h`) is the main control; the KRL covers the gap until expiry.

## 6. Audit what is in use

```bash
# Which certificates logged on (sshd logs key ID, serial and CA fingerprint)
journalctl -u ssh -u sshd --since -1d | grep -E 'Accepted publickey .* (ID|CA) '
# Plain keys that are still accepted on this host
find /home /root -name authorized_keys -path '*/.ssh/*' -exec wc -l {} +
```

## 7. Verify

- [ ] `ssh-keygen -L` on a fresh user certificate shows the expected principals, a short validity and
      only the needed `permit-*` options.
- [ ] A certificate whose principal is not in `auth_principals/<user>` is refused.
- [ ] An expired certificate and a serial in the KRL are both refused (`sshd` log shows why).
- [ ] Clients connect to a new server with no host key prompt; a host outside the `@cert-authority`
      pattern still prompts.
- [ ] The CA private keys are offline or token-backed and their passphrase is in the owner's vault.
- [ ] `/etc/ssh/user_ca.pub`, `auth_principals/` and the KRL are watched by [file integrity monitoring](../assurance/file-integrity-monitoring.md).

ATT&CK relevance: stolen SSH keys and certificates are used for **T1021.004** (Remote Services: SSH);
an attacker who adds a CA to `TrustedUserCAKeys` gets persistence like **T1098.004** (Account
Manipulation: SSH Authorized Keys).

## Related

- [Deploy SSH keys](ssh-key-deployment.md)
- [Join Linux to Active Directory (realm, SSSD)](linux-active-directory-join-sssd.md)
- [Credential rotation after compromise](../incident-response/credential-rotation-after-compromise.md)
- [Manage certificates and PKI](certificate-and-pki-management.md)

## Sources

- [ssh-keygen(1): CERTIFICATES, KEY REVOCATION LISTS](https://man.openbsd.org/ssh-keygen.1)
- [sshd_config(5)](https://man.openbsd.org/sshd_config.5), [ssh_config(5)](https://man.openbsd.org/ssh_config.5), [sshd(8): SSH_KNOWN_HOSTS FILE FORMAT](https://man.openbsd.org/sshd.8)
- [OpenSSH Server configuration for Windows](https://learn.microsoft.com/windows-server/administration/openssh/openssh-server-configuration)
