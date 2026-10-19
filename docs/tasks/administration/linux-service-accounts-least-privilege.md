---
title: Linux Service Accounts with Least Privilege
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
  - service accounts
  - least privilege
  - setfacl
  - sudoers
  - polkit
  - systemd
  - credentials
  - nologin
aliases: [create service account linux, linux service user, run service as non-root, useradd --system, nologin user, give user read access to folder, setfacl default acl, allow user to restart one service, sudo restart service only, polkit restart unit, systemd LoadCredential, systemd-creds, DynamicUser, service account private key permissions, permission denied service account]
---

# Linux Service Accounts with Least Privilege

*"The app runs as root because it was easier."* *"The service gets `Permission denied` on its key file."* *"The ops team
needs to restart one service without full sudo."* This workflow creates a dedicated account for one service and gives
it exactly the access it needs, and no more, on files, folders, other services, keys and secrets. Everything is done
from the shell.

!!! warning "Before you run anything"
    Creating accounts, changing ownership and editing sudoers or polkit rules changes who can do what on the host. Try
    it on a test VM first, keep a copy of any file you edit (`getfacl -R -p` for ACLs, a copy of the sudoers drop-in),
    and keep a root shell open while you change sudo rules. Commands are checked against the man pages listed under
    Sources (useradd, setfacl, sudoers, polkit, systemd.exec, systemd-creds); they were not run on a live host for
    this page. The example account is `appsvc` and the example service is `appsvc.service` — replace both.

## The model: who owns what

A service account should be able to **read** its code and configuration, **write** only its own data and logs, and
**read** its secrets — never change them, and never change its own program. If an attacker takes over the process,
that is all they get.

| Path (example) | Owner:group | Mode | Why |
| --- | --- | --- | --- |
| `/opt/appsvc/` (program) | `root:root` | `0755` dirs, `0644`/`0755` files | The service runs the code but cannot replace it |
| `/etc/appsvc/` (config) | `root:appsvc` | `0750` dir, `0640` files | Readable by the service, editable only by root |
| `/etc/appsvc/secret.key` | `root:appsvc` | `0640` (or `0440`) | Readable, not writable; the owner (root) is the only one who can change the mode |
| `/var/lib/appsvc/` (state) | `appsvc:appsvc` | `0750` | The only place the service writes data |
| `/var/log/appsvc/` (logs) | `appsvc:adm` | `0750` | The service writes; the `adm` group (log readers) can read |

Do not make the service account the **owner** of its secrets or binaries: the owner of a file can always `chmod` it.

## 1. Create the account

```bash
# A system account: UID from the system range, no password aging, no home directory created
sudo useradd --system --user-group \
  --home-dir /var/lib/appsvc --no-create-home \
  --shell /usr/sbin/nologin \
  --comment "appsvc service account" appsvc

id appsvc                       # uid=9xx(appsvc) gid=9xx(appsvc) groups=9xx(appsvc)
sudo passwd -S appsvc           # status L (locked) or LK: no password, nobody can log in with one
getent passwd appsvc            # shell must be nologin (or /bin/false)
```

On distributions where `nologin` lives in `/sbin` the merged `/usr` makes `/usr/sbin/nologin` work too; check with
`ls -l /usr/sbin/nologin`.

Lock it, do not expire it. A locked password stops password logins. Setting an account expiry date (`chage -E 0`)
also makes PAM refuse cron jobs for the account, which breaks scheduled work that runs as the service.

**Declarative alternative (survives rebuilds):** a `sysusers.d` file creates the account at boot or package install.

```bash
# Fields: type name id "GECOS" home shell   ("-" = pick a free system UID)
echo 'u appsvc - "appsvc service account" /var/lib/appsvc /usr/sbin/nologin' |
  sudo tee /etc/sysusers.d/appsvc.conf
sudo systemd-sysusers /etc/sysusers.d/appsvc.conf
```

Never add a service account to `sudo`/`wheel`, `docker`, `lxd`, `disk` or `shadow`: each one is root, or reads every
password hash, in a different form.

## 2. Files and folders: ownership and modes

```bash
# Program: root owns it, the service can only read and execute
sudo chown -R root:root /opt/appsvc
sudo chmod -R u=rwX,go=rX /opt/appsvc

# Config: root owns, group appsvc reads
sudo install -d -o root -g appsvc -m 0750 /etc/appsvc
sudo chown root:appsvc /etc/appsvc/app.conf
sudo chmod 0640 /etc/appsvc/app.conf

# State and logs: the only writable places
sudo install -d -o appsvc -g appsvc -m 0750 /var/lib/appsvc
sudo install -d -o appsvc -g adm    -m 0750 /var/log/appsvc
```

`X` (capital) sets execute only on directories and files that are already executable, so `chmod -R` does not make
every config file executable.

**Shared folder that several accounts write to:** give the folder a group and the set-group-ID bit, so new files
belong to that group instead of the creator's primary group.

```bash
sudo groupadd --system appdata
sudo usermod -aG appdata appsvc
sudo install -d -o root -g appdata -m 2770 /srv/appdata      # 2 = setgid: new files inherit group appdata
```

New files still get the creating process's umask. systemd services default to `UMask=0022` (group can read, not
write); set `UMask=0007` in the unit (section 5) if group members must write each other's files.

## 3. Files and folders: ACLs for "one more account"

Use an ACL when an account needs access to something it should not own or share a group with — for example a
private key in `/etc/ssl/private`, or a log folder another team reads.

```bash
# Read one file. The account also needs search (x) on every parent folder.
sudo setfacl -m u:appsvc:r /etc/ssl/private/appsvc.key
sudo setfacl -m u:appsvc:x /etc/ssl/private

# Read a whole tree, now and for files created later (-d = default ACL on folders)
sudo setfacl -R    -m g:auditors:rX /var/log/appsvc
sudo setfacl -R -d -m g:auditors:rX /var/log/appsvc

getfacl /etc/ssl/private/appsvc.key      # look for user:appsvc:r-- and "#effective:" warnings
ls -l /etc/ssl/private/appsvc.key        # a trailing + on the mode means an ACL is set
```

Sample output of `getfacl`:

```text
# file: etc/ssl/private/appsvc.key
# owner: root
# group: root
user::rw-
user:appsvc:r--
group::---
mask::r--
other::---
```

- The **mask** caps every named entry. `chmod g-r` on a file with an ACL lowers the mask and silently removes the
  ACL grant; `getfacl` then prints `#effective:---`. Re-apply with `setfacl -m m::r`.
- **Remove** a grant with `setfacl -x u:appsvc <file>`; remove all ACLs with `setfacl -b <file>`.
- **Back up and restore** before bulk changes: `getfacl -R -p /srv/appdata > appdata.acl` and
  `sudo setfacl --restore=appdata.acl`.
- ext4, XFS and Btrfs support POSIX ACLs out of the box. NFSv4 shares use `nfs4_setfacl` instead.
- Debian/Ubuntu alternative for TLS keys: `/etc/ssl/private` is group `ssl-cert`, so
  `sudo usermod -aG ssl-cert appsvc` gives read access to every key there. Prefer the per-file ACL when the host holds
  keys for more than one service.

## 4. Check access as the account

A `nologin` shell blocks logins, not commands run on the account's behalf. Test as the account before you start the
service:

```bash
sudo -u appsvc test -r /etc/appsvc/app.conf      && echo "read config: OK"
sudo -u appsvc test -w /etc/appsvc/app.conf      && echo "PROBLEM: config writable"
sudo -u appsvc test -w /opt/appsvc/bin/appsvc    && echo "PROBLEM: binary writable"
sudo -u appsvc test -w /var/lib/appsvc           && echo "write state: OK"
sudo -u appsvc cat /etc/ssl/private/appsvc.key >/dev/null && echo "read key: OK"

namei -l /etc/ssl/private/appsvc.key      # owner and mode of every folder on the path: finds the missing x
```

`runuser -u appsvc -- <command>` (util-linux, root only) does the same without sudo. `su appsvc` fails by design;
use `su -s /bin/sh appsvc` only when you really need an interactive shell for debugging.

## 5. Run the service as the account (systemd)

Put access rules in the unit, not only in file modes: systemd can make the rest of the system read-only for the
service even if a file mode is wrong.

```bash
sudo systemctl edit appsvc.service      # creates /etc/systemd/system/appsvc.service.d/override.conf
```

```ini
[Service]
User=appsvc
Group=appsvc
# Writable places, created with the right owner on start
StateDirectory=appsvc
LogsDirectory=appsvc
# Everything else read-only, home folders hidden, own /tmp
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
# Only if it must bind a port below 1024 as non-root; otherwise leave capabilities empty
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
UMask=0027
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart appsvc.service
systemctl show appsvc.service -p User -p Group -p ProtectSystem -p StateDirectory
systemd-analyze security appsvc.service     # exposure score and the settings still open
```

- `ProtectSystem=strict` mounts the whole file system read-only for the service, except `/dev`, `/proc` and `/sys`.
  `StateDirectory=`, `LogsDirectory=` (and `CacheDirectory=`, `RuntimeDirectory=`) stay writable; any other path
  must be listed in `ReadWritePaths=`.
- A `ReadWritePaths=` entry does not override file modes: the account still needs write permission there.
- **No account at all:** `DynamicUser=yes` allocates a UID only while the service runs and implies
  `ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes` and `RestrictSUIDSGID=yes`. Good for
  stateless services; files outside `StateDirectory=` cannot be owned by a UID that changes, so use ACLs for groups
  or the credential mechanism below for secrets.

## 6. Secrets and keys for the service

Keep passwords and tokens out of the unit file, the environment and the program folder. Environment variables are
readable through `/proc/<pid>/environ` by the same user and root, and are inherited by every child process.

**systemd credentials (systemd 247+, encrypted from 250):** systemd reads the secret as root and hands the service a
read-only copy that only the service's UID (and root) can read, in unswappable memory where supported.

```bash
# Plain file kept by root (simplest)
sudo install -d -o root -g root -m 0700 /etc/credstore
sudo install -o root -g root -m 0600 /dev/null /etc/credstore/appsvc-db-password
sudoedit /etc/credstore/appsvc-db-password

# Or encrypted at rest with the host key and/or TPM2 (systemd 250+); prompts, never echoes
sudo install -d -m 0700 /etc/credstore.encrypted
systemd-ask-password -n "DB password:" |
  sudo systemd-creds encrypt --name=appsvc-db-password - /etc/credstore.encrypted/appsvc-db-password
```

```ini
[Service]
# Plain: LoadCredential=ID:PATH; encrypted: LoadCredentialEncrypted=ID (searches /etc/credstore.encrypted/)
LoadCredentialEncrypted=appsvc-db-password
```

The program reads `$CREDENTIALS_DIRECTORY/appsvc-db-password`. If it only accepts a path in its config file, point it
at `%d/appsvc-db-password` in `ExecStart=` (`%d` expands to the credentials directory). `--with-key=` chooses `host`,
`tpm2`, `host+tpm2` or `auto` (default); a credential bound to the TPM cannot be decrypted on another machine.

**Files the service reads directly** (TLS keys, keytabs, SSH keys): `root:appsvc 0640` or a per-file ACL as in
section 3. An SSH client key the service uses to connect out lives in the account's home, owned by the account:

```bash
sudo install -d -o appsvc -g appsvc -m 0700 /var/lib/appsvc/.ssh
sudo -u appsvc ssh-keygen -t ed25519 -N '' -C "appsvc@$(hostname)" -f /var/lib/appsvc/.ssh/id_ed25519
```

On the receiving side, pin that key to one command so a stolen key cannot open a shell:

```text
restrict,command="/usr/local/bin/receive-backup" ssh-ed25519 AAAA... appsvc@app01
```

Encrypted credentials in depth, the kernel keyring, SOPS, Vault/OpenBao and rotation steps per store:
[Store service secrets & keys on Linux](linux-service-secrets-storage.md).

## 7. Let people manage the service without full root

### sudo: exact commands only

```bash
sudo groupadd --system appsvc-ops
sudo visudo -f /etc/sudoers.d/appsvc-ops
```

```text
# /etc/sudoers.d/appsvc-ops  (mode 0440; no dot or trailing ~ in the file name, or sudo ignores it)
Cmnd_Alias APPSVC_CTL = /usr/bin/systemctl start appsvc.service, \
                        /usr/bin/systemctl stop appsvc.service, \
                        /usr/bin/systemctl restart appsvc.service
%appsvc-ops ALL=(root) APPSVC_CTL
%appsvc-ops ALL=(root) sudoedit /etc/appsvc/app.conf
```

```bash
sudo visudo -c                        # syntax of sudoers and every drop-in
sudo -l -U <OPS_USER>                 # what that user may now run
```

- Arguments in a sudoers rule must match exactly, so `systemctl restart appsvc.service` does not allow restarting
  anything else. A command with no arguments listed allows **any** arguments.
- Do not grant `systemctl status`, `journalctl`, `less`, `vi` or anything that opens a pager or editor as root: they
  can start a shell. `systemctl status` works without sudo; add operators to `systemd-journal` (or `adm`) to read the
  service's logs. Use `sudoedit` for config files — the user edits a copy as themselves.
- Never grant a script or binary that the ops group (or the service account) can write.

### polkit: restart without sudo

`systemctl` asks polkit when an unprivileged user manages a unit, and systemd passes the unit name and the operation
(`unit`, `verb`) to the rule. This rule lets `appsvc-ops` start, stop and restart only `appsvc.service`:

```javascript
// /etc/polkit-1/rules.d/50-appsvc-ops.rules
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") == "appsvc.service" &&
        subject.isInGroup("appsvc-ops")) {
        var verb = action.lookup("verb");
        if (verb == "start" || verb == "stop" || verb == "restart") {
            return polkit.Result.YES;
        }
    }
});
```

```bash
# As a member of appsvc-ops, no sudo:
systemctl restart appsvc.service
```

polkit reloads rule files automatically. JavaScript `.rules` files need polkit 0.106 or later; older releases (for
example Ubuntu 22.04's 0.105) use `.pkla` files and cannot match on the unit name, so use the sudo rule there.

## 8. Review and remove

```bash
id appsvc; sudo passwd -S appsvc; sudo chage -l appsvc
sudo -l -U appsvc                                  # should be "not allowed to run sudo"
sudo find / -xdev -user appsvc -ls 2>/dev/null     # everything the account owns
sudo find / -xdev -perm -0002 \( -type f -o -type d \) 2>/dev/null   # world-writable: review
sudo lastlog -u appsvc      # or lastlog2; "Never logged in" is the healthy result
systemctl show -p User --value appsvc.service

# Retire: stop the service first, then remove the account and look for leftovers
sudo systemctl disable --now appsvc.service
sudo userdel appsvc
sudo find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null
```

Watch the secret file with auditd (`-w /etc/appsvc/secret.key -p rwa -k appsvc-secret`, see [auditd](../../platforms/linux/auditd.md))
and alert on any interactive login by a service account: that is ATT&CK
[T1078.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003/). Broad sudo grants are
[T1548.003](https://attack.mitre.org/techniques/T1548/003/) waiting to happen; audit them with the
[sudoers integrity check](../assurance/linux-sudoers-integrity.md).

## Other Unix systems

- **FreeBSD:** `pw useradd -n appsvc -c "appsvc service account" -d /nonexistent -s /usr/sbin/nologin`; UFS needs the
  `acls` mount option for `setfacl`, ZFS uses NFSv4 ACLs (`setfacl -a 0 user:appsvc:read_data::allow <file>`). Services
  set the user in `/etc/rc.conf` (for example `<service>_user="appsvc"`) where the rc script supports it.
- **macOS:** service accounts start with `_` and have a UID below 500, created with `dscl . -create /Users/_appsvc`
  plus `UniqueID`, `PrimaryGroupID`, `UserShell /usr/bin/false` and `NFSHomeDirectory /var/empty`; grant file access
  with `chmod +a "user:_appsvc allow read" <file>` and run the job through a launchd plist with `UserName`.

## Related

- [Credential rotation after a compromise](../incident-response/credential-rotation-after-compromise.md): the incident-response order for rotating these accounts and secrets
- [Service account audit script (NDJSON)](../assurance/service-account-audit.md): shells, passwords, sudo grants and unit users on a whole host
- [Windows service accounts with least privilege](windows-service-accounts-least-privilege.md)
- [Linux users and permissions](../../platforms/linux/users-permissions.md)
- [Local user & group management](local-user-group-management.md)
- [systemd](../../platforms/linux/systemd.md) · [Linux service failure](../troubleshooting/linux-service-failure.md)
- [SSH key deployment](ssh-key-deployment.md)
- [Environment variables and PATH](environment-variables-and-path.md)
- [Users, groups & permissions (concept)](../../fundamentals/concepts/users-groups-permissions.md)

## Sources

- [useradd(8)](https://man7.org/linux/man-pages/man8/useradd.8.html) · [passwd(1)](https://man7.org/linux/man-pages/man1/passwd.1.html) · [chage(1)](https://man7.org/linux/man-pages/man1/chage.1.html) · [sysusers.d(5)](https://www.freedesktop.org/software/systemd/man/latest/sysusers.d.html)
- [setfacl(1)](https://man7.org/linux/man-pages/man1/setfacl.1.html) · [getfacl(1)](https://man7.org/linux/man-pages/man1/getfacl.1.html) · [acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html) (mask and effective rights) · [namei(1)](https://man7.org/linux/man-pages/man1/namei.1.html) · [runuser(1)](https://man7.org/linux/man-pages/man1/runuser.1.html)
- [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) (User=, DynamicUser=, ProtectSystem=, StateDirectory=, UMask=, LoadCredential=, credential search paths) · [systemd-creds(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html) · [systemd-analyze(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)
- [sudoers(5)](https://www.sudo.ws/docs/man/sudoers.man/) (command arguments, sudoedit, #includedir file names) · [visudo(8)](https://www.sudo.ws/docs/man/visudo.man/)
- [polkit(8)](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html) (rules.d, action.lookup) · [org.freedesktop.systemd1(5)](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) (manage-units); the `unit`/`verb` details come from systemd 226 (NEWS) and `src/core/dbus-util.c`
- [sshd(8) — authorized_keys options](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT) (restrict, command=)
- [FreeBSD pw(8)](https://man.freebsd.org/cgi/man.cgi?query=pw&sektion=8) · [FreeBSD setfacl(1)](https://man.freebsd.org/cgi/man.cgi?query=setfacl&sektion=1)
- [MITRE ATT&CK — T1078.003](https://attack.mitre.org/techniques/T1078/003/) · [T1548.003](https://attack.mitre.org/techniques/T1548/003/)
