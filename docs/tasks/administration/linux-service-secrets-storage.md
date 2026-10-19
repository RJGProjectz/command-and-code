---
title: Store Service Secrets & Keys on Linux
type: workflow
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-18
difficulty: intermediate
category: Identity
tags:
  - secrets
  - credentials
  - systemd-creds
  - keyring
  - sops
  - age
  - vault
  - openbao
  - rotation
aliases: [where to store service password linux, linux service secrets, systemd credentials, systemd-creds encrypt, LoadCredentialEncrypted, credstore, tpm2 bound secret, EnvironmentFile secret, environment variable password systemd, kernel keyring keyctl, keyctl padd, sops age, encrypt config file sops, sops exec-env, sops rotate, hashicorp vault approle, openbao approle, vault agent secret file, rotate service password linux, who can read service secret]
---

# Store Service Secrets & Keys on Linux

*"Where do I put the database password so only the service can read it?"* *"Is `EnvironmentFile=` safe?"*
*"How do I rotate the API token without editing five files?"* This workflow picks a store for each secret a service
needs, shows who can read it, and gives the rotation steps for each store. It builds on
[Linux service accounts with least privilege](linux-service-accounts-least-privilege.md), which creates the account
(`appsvc`) and the folders used here.

!!! warning "Before you run anything"
    These commands create and replace secrets. Keep the old value until the service has restarted and works with the
    new one, and never paste a real secret on the command line (it lands in shell history and `ps` output): every
    example reads the value from a prompt or stdin. Commands are checked against the vendor documentation listed under
    Sources (systemd.exec, systemd-creds, keyctl, SOPS, Vault/OpenBao); they were not run on a live host for this page.

## Pick a store

| Store | Encrypted at rest | Who can read it | Good for |
| :--- | :--- | :--- | :--- |
| `Environment=` in the unit | No | **Any local user** (unit properties are public over D-Bus) | Nothing secret |
| `EnvironmentFile=` (root 0600) | No | root; then the process, its children, and `/proc/<pid>/environ` for the same UID | Legacy apps that only read env vars |
| Plain file `root:appsvc 0640` | No | root and group `appsvc` | Keys the program opens itself (TLS, keytab) |
| systemd `LoadCredential=` | No (source file) | root; a read-only copy for the unit's UID only | Most services on systemd 247+ |
| systemd `LoadCredentialEncrypted=` | Yes: host key and/or TPM2 | root on **this** host; the unit's UID at run time | The default choice on systemd 250+ |
| Kernel keyring (`keyctl`) | In kernel memory only, gone at reboot | Per keyring permission mask | Caching a token in memory for a while |
| SOPS + age file | Yes (age recipients) | Whoever holds an age private key | Secrets kept in git with the config |
| Vault / OpenBao | Yes (server side) | Whoever holds a token with a policy on the path | Many hosts, audit log, short-lived and dynamic secrets |

The rule of thumb: **systemd encrypted credentials for one host, SOPS for config in git, Vault/OpenBao for a fleet.**
Cloud workloads should read from the cloud store with the instance's own identity instead (see
[Cloud secret stores](#cloud-secret-stores)).

## 1. Why not environment variables

systemd.exec(5) says environment variables are not suitable for passing secrets: `Environment=` values are exposed to
unprivileged clients over D-Bus, and every variable is inherited down the process tree, including into setuid programs
the service runs. `EnvironmentFile=` keeps the value out of the unit, but once loaded it is still an environment variable.
Check what a unit leaks today:

```bash
# Run as an ordinary user: anything printed here is readable by every local account
systemctl show appsvc.service -p Environment

# Units that still put secrets on the command line or in Environment=
sudo grep -rniE '(pass(word)?|token|secret|api[_-]?key)=' /etc/systemd/system /run/systemd/system 2>/dev/null
```

If the program can only read an environment variable, keep `EnvironmentFile=` (file `root:root 0600`, read by PID 1
before it drops privileges) and plan the move to a credential file.

## 2. systemd credentials (one host)

The service gets a read-only copy at `$CREDENTIALS_DIRECTORY/<id>` (for system services also
`/run/credentials/<unit>/<id>`), readable only by the unit's `User=` and root, in non-swappable memory where possible.
The source only needs to be readable by root. [Section 6](linux-service-accounts-least-privilege.md#6-secrets-and-keys-for-the-service)
of the service-account page shows the plain form; the encrypted form is better:

```bash
# Does this host have a usable TPM2? (systemd 251+; prints yes/no/partial)
systemd-analyze has-tpm2

sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted
# Prompt without echo, encrypt with the host key + TPM2 (default 'auto' picks what exists)
systemd-ask-password -n "appsvc DB password:" |
  sudo systemd-creds encrypt --name=appsvc-db-password - /etc/credstore.encrypted/appsvc-db-password
```

```ini
# /etc/systemd/system/appsvc.service.d/credentials.conf
[Service]
# No path: searched in /run/credstore.encrypted, /etc/credstore.encrypted, /usr/lib/credstore.encrypted
LoadCredentialEncrypted=appsvc-db-password
# Program wants a path in an env var? Pass the path, never the value
Environment=DB_PASSWORD_FILE=%d/appsvc-db-password
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart appsvc.service
# The decrypted copy exists only while the unit runs
sudo ls -l /run/credentials/appsvc.service/
```

- `--with-key=` takes `host`, `tpm2`, `host+tpm2`, `auto` (default) or `null`. `tpm2` binds the secret to this
  machine's TPM: a copied file or disk image cannot be decrypted elsewhere. `null` gives no protection, avoid it.
- `--pretty` with `--name=` and `-` as output prints a `SetCredentialEncrypted=` line to paste into the unit instead
  of a file. Fine for small values; the unit file then needs the same care as the credential.
- systemd 262 also pins TPM2 credentials to the TPM storage key, so they do not decrypt on older systemd versions.
  Re-encrypt after a downgrade.
- The total size of credentials per unit is limited to 1 MB.

**Rotate:** encrypt the new value to the same path (`systemd-creds encrypt ... /etc/credstore.encrypted/<id>`), then
`systemctl restart` the unit: the credential is copied in only when the service starts. After a TPM reset or
motherboard swap, TPM-bound credentials must be re-created from the source of truth.

## 3. Kernel keyring (in memory, short-lived)

The kernel keyring holds small secrets in kernel memory with a permission mask per key; nothing is written to disk and
everything is gone at reboot. It suits caching a token that a script fetched from a vault, not long-term storage.
System services get a **private** session keyring by default (`KeyringMode=private`), so two services that run as the
same UID do not share keys unless you set `KeyringMode=shared`.

```bash
# Add a token to the session keyring from stdin, expire it after 1 hour
keyid=$(printf '%s' "$token" | keyctl padd user appsvc:api-token @s)
keyctl timeout "$keyid" 3600

# Read it back (raw bytes, no newline), list, and remove
keyctl pipe "$keyid"
keyctl show @s
keyctl revoke "$keyid"
```

`keyctl search @s user appsvc:api-token` finds a key by its description. `keyctl setperm <key> <mask>` narrows access;
read the mask bits in keyctl(1) before changing them, a wrong mask can make the key unreadable to its own owner.

## 4. SOPS + age (encrypted files in git)

SOPS encrypts the **values** in YAML, JSON, ENV, INI or binary files and leaves the keys readable, so diffs and reviews
still work. age is the simplest key type: one private key per host or person.

```bash
# On the host: one age key for the service, readable by root only
sudo install -d -o root -g root -m 0700 /etc/appsvc/age
sudo age-keygen -o /etc/appsvc/age/keys.txt        # prints the public key: age1...
sudo chmod 0600 /etc/appsvc/age/keys.txt
```

```yaml
# .sops.yaml at the repo root: which recipients encrypt which files
creation_rules:
  - path_regex: secrets/appsvc/.*\.yaml$
    age: >-
      age1host...app01,
      age1admin...alice
```

```bash
# Encrypt (current releases; older ones use sops -e / sops -d)
sops encrypt secrets/appsvc/prod.yaml > secrets/appsvc/prod.enc.yaml
sops edit secrets/appsvc/prod.enc.yaml                 # opens decrypted in $EDITOR, re-encrypts on save

# Read on the host. Default key file is ~/.config/sops/age/keys.txt; point root at the service key instead
sudo SOPS_AGE_KEY_FILE=/etc/appsvc/age/keys.txt sops decrypt --extract '["db"]["password"]' prod.enc.yaml
```

Hand the values to the program without writing plaintext to disk:

```bash
# As environment variables of one child process (same env-var caveats as section 1)
sudo SOPS_AGE_KEY_FILE=/etc/appsvc/age/keys.txt sops exec-env --user appsvc prod.enc.yaml '/opt/appsvc/bin/appsvc'
# As a file: a FIFO by default, readable once; {} is replaced with its path
sudo SOPS_AGE_KEY_FILE=/etc/appsvc/age/keys.txt sops exec-file --user appsvc prod.enc.yaml '/opt/appsvc/bin/appsvc --config {}'
```

Or decrypt once at deploy time into a systemd encrypted credential (section 2), so the running host never needs the
age key in the service path.

**Rotate:**

- New value: `sops edit` (or `sops set file '["db"]["password"]' --value-stdin`), commit, redeploy.
- Recipients changed (person left, host rebuilt): edit `.sops.yaml`, run `sops updatekeys prod.enc.yaml`, then
  `sops rotate -i prod.enc.yaml` to create a new data key. A removed person who kept an old copy of the file can still
  read the **old** values, so also change the secrets they could see.

## 5. HashiCorp Vault / OpenBao (many hosts)

OpenBao is the open-source fork of Vault; its CLI is `bao` with the same AppRole commands shown here for `vault`.
AppRole gives a service a **RoleID** (like a user name, not secret) and a **SecretID** (secret, short-lived, limited
uses). The service exchanges both for a token that carries only its policy.

```hcl
# appsvc.hcl: read-only on its own KV v2 path
path "secret/data/appsvc/*" {
  capabilities = ["read"]
}
```

```bash
# Admin, once
vault policy write appsvc appsvc.hcl
vault auth enable approle
vault write auth/approle/role/appsvc \
    token_policies=appsvc token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=24h secret_id_num_uses=1 secret_id_bound_cidrs=10.0.10.0/24

# Put the secret from stdin, never on the command line (a put writes a new version)
systemd-ask-password -n "DB password:" | vault kv put -mount=secret appsvc/db password=-

# Deliver the IDs to the host as root-only files
vault read -field=role_id auth/approle/role/appsvc/role-id | sudo tee /etc/vault-agent/role-id >/dev/null
vault write -f -field=secret_id auth/approle/role/appsvc/secret-id | sudo tee /etc/vault-agent/secret-id >/dev/null
sudo chmod 0600 /etc/vault-agent/role-id /etc/vault-agent/secret-id
```

Run **Vault Agent** (or OpenBao Agent) on the host so the service never handles tokens. It logs in with AppRole,
deletes the SecretID file after reading it (`remove_secret_id_file_after_reading` defaults to true), renews the
token, and renders the secret into a file the service reads:

```hcl
# /etc/vault-agent/agent.hcl
auto_auth {
  method {
    type = "approle"
    config = {
      role_id_file_path   = "/etc/vault-agent/role-id"
      secret_id_file_path = "/etc/vault-agent/secret-id"
    }
  }
}

template {
  contents    = "{{ with secret \"secret/data/appsvc/db\" }}{{ .Data.data.password }}{{ end }}"
  destination = "/run/appsvc/db-password"
  perms       = "0640"          # unset = 0644 for a new file
  exec {
    command = ["systemctl", "reload-or-restart", "appsvc.service"]
  }
}
```

Give `/run/appsvc` to `root:appsvc` (mode `0750`) so only the service group reads the rendered file. To keep the
SecretID secret in transit, generate it with response wrapping (`vault write -wrap-ttl=5m -f
auth/approle/role/appsvc/secret-id`) and set `secret_id_response_wrapping_path` in the agent config: whoever unwraps it
first wins, so a stolen copy is detected when the real agent fails to log in.

**Rotate:**

- Secret value: `vault kv put` a new version; the agent re-renders the file and runs the `exec` command.
- SecretID: write a new one to the host, then destroy the old one by accessor
  (`vault list auth/approle/role/appsvc/secret-id`, `vault write auth/approle/role/appsvc/secret-id-accessor/destroy
  secret_id_accessor=<accessor>`).
- Database passwords: Vault's database secrets engine can issue a new short-lived login per lease, so there is no
  long-lived password left to rotate.

## Cloud secret stores

On a cloud VM, use the instance's own identity rather than a stored key:

```bash
# Azure: VM managed identity
az login --identity
az keyvault secret show --vault-name kv-app --name appsvc-db --query value -o tsv
# AWS: instance profile role
aws secretsmanager get-secret-value --secret-id appsvc/db --query SecretString --output text
# GCP: VM service account
gcloud secrets versions access latest --secret=appsvc-db
```

Access control, rotation and audit for each: [Azure Key Vault](../../platforms/azure/keys-secrets.md) ·
[AWS keys & secrets](../../platforms/aws/keys-secrets.md) · [GCP keys & secrets](../../platforms/gcp/keys-secrets.md).
Write the value into a systemd credential or a `0640` file rather than an environment variable.

## 6. Who can read the secret?

```bash
# Ownership, mode and ACL of every secret file (a '+' after the mode means an ACL exists)
sudo ls -l /etc/credstore* /etc/appsvc /run/appsvc
sudo getfacl -p /etc/appsvc/* 2>/dev/null | grep -v '^#'

# Can the service account (and only it) read it?
sudo -u appsvc test -r /run/appsvc/db-password && echo "appsvc: readable"
sudo -u nobody test -r /run/appsvc/db-password && echo "nobody: READABLE - fix it"

# Secret-looking files readable by everyone
sudo find /etc /opt /srv -xdev -type f -perm -o=r \( -name '*.key' -o -name '*secret*' -o -name '*.pem' -o -name '*token*' \) 2>/dev/null
```

Watch the secret paths with auditd so every read is logged:
`-w /etc/credstore.encrypted -p rwa -k svc-secret` and `-w /etc/appsvc/age -p rwa -k svc-secret` (see
[auditd](../../platforms/linux/auditd.md)). Vault/OpenBao keep their own audit log once an audit device is enabled.

## Related

- [Credential rotation after a compromise](../incident-response/credential-rotation-after-compromise.md): the incident-response order for rotating these accounts and secrets
- [Service account audit script](../assurance/service-account-audit.md): finds world-readable files in the systemd credential stores
- [Linux service accounts with least privilege](linux-service-accounts-least-privilege.md) · [Windows service secrets](windows-service-secrets-storage.md)
- [systemd](../../platforms/linux/systemd.md) · [auditd](../../platforms/linux/auditd.md) · [Linux users and permissions](../../platforms/linux/users-permissions.md)
- [SSH key deployment](ssh-key-deployment.md) · [Environment variables and PATH](environment-variables-and-path.md)
- [Cryptography fundamentals](../../fundamentals/concepts/cryptography-fundamentals.md)

## Sources

- [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) (environment variables not for secrets, D-Bus exposure; LoadCredential=, LoadCredentialEncrypted=, SetCredentialEncrypted=, ImportCredential=, search paths, 1 MB limit, %d; KeyringMode=) · [systemd-creds(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html) (--with-key=, --name=, --pretty, list/cat, v262 SRK pinning) · [systemd-analyze(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html) (has-tpm2)
- [keyctl(1)](https://man7.org/linux/man-pages/man1/keyctl.1.html) · [keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
- SOPS — [age identities](https://getsops.io/docs/usage/identities/age/) (key file location, SOPS_AGE_KEY_FILE) · [Common operations](https://getsops.io/docs/usage/common-operations/) · [Key management](https://getsops.io/docs/usage/key-management/) (updatekeys, rotate) · [Advanced](https://getsops.io/docs/usage/advanced/) (exec-env, exec-file, FIFO, --user)
- HashiCorp Vault — [AppRole auth](https://developer.hashicorp.com/vault/docs/auth/approle) · [AppRole API](https://developer.hashicorp.com/vault/api-docs/auth/approle) (token_policies, secret_id_bound_cidrs, secret-id-accessor/destroy) · [kv put](https://developer.hashicorp.com/vault/docs/commands/kv/put) (key=- from stdin) · [Agent AppRole auto-auth](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth/methods/approle) · [CLI global flags](https://developer.hashicorp.com/vault/docs/commands) (-wrap-ttl)
- [OpenBao — AppRole auth](https://openbao.org/docs/auth/approle/) (`bao` CLI)
- MITRE ATT&CK — [T1552.001 Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) · [T1552.004 Private Keys](https://attack.mitre.org/techniques/T1552/004/)
