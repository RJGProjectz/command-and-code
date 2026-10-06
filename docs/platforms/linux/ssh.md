---
title: Linux SSH
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Hardening, Administration]
category: Remote Access
tags: [ssh, authorized_keys, sshd_config, persistence, hardening]
aliases: [authorized keys, ssh keys persistence, sshd -T, disable root login, ssh hardening]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux SSH

## Find authorized keys

Adding a key to `authorized_keys` is a quiet persistence method ([T1098.004](https://attack.mitre.org/techniques/T1098/004/)).

```bash
sudo find / -xdev -name 'authorized_keys*' -type f -exec ls -l {} \; 2>/dev/null
sudo sh -c 'awk "{print FILENAME\": \"\$0}" /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null'
```

Fingerprints (to compare with `Accepted publickey ... SHA256:...` log lines):

```bash
ssh-keygen -lf '/home/<USER>/.ssh/authorized_keys'
```

`sshd` can be configured to read keys from elsewhere — check the effective `AuthorizedKeysFile`.

## Effective server configuration

```bash
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|port |allowusers|allowgroups'
```

`sshd -T` prints the configuration actually in force, including `/etc/ssh/sshd_config.d/*.conf` drop-ins (included by default on current Debian, Ubuntu and RHEL).

## Hardening baseline

```text
# /etc/ssh/sshd_config.d/10-hardening.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
```

Validate before restarting — a syntax error can lock you out:

```bash
sudo sshd -t && sudo systemctl reload ssh     # unit is 'sshd' on RHEL-family
```

## Who connected

```bash
sudo grep -E 'Accepted (publickey|password)' /var/log/auth.log
journalctl -u ssh --since "-7d" | grep Accepted
```

## Active SSH sessions

```bash
who
sudo ss -tnp state established '( sport = :22 )'
```

## Client-side debugging

```bash
ssh -v user@host
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@host
```

## Related

- [Linux logs](logs.md#failed-ssh-logins)
- [Account Compromise workflow](../../tasks/incident-response/account-compromise.md)

## Sources

- [sshd_config(5)](https://man.openbsd.org/sshd_config)
- [sshd(8) -T](https://man.openbsd.org/sshd)
