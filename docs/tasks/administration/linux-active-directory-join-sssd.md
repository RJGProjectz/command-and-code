---
title: Join Linux to Active Directory (realm, SSSD)
type: workflow
platforms: [Linux, Windows Server]
languages: [Bash, PowerShell]
tasks: [Administration, Hardening]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [active-directory, sssd, realmd, kerberos, keytab, linux, access-control, sudo]
aliases: [realm join, realm discover, realm permit, sssd.conf, sssd ad provider, ad_access_filter, simple_allow_groups, ad_gpo_access_control, linux domain join, join ubuntu to active directory, join rhel to active directory, krb5.keytab, klist -k, sudo for ad group, sssctl, sssd troubleshooting, kerberos clock skew, adcli]
difficulty: intermediate
verified: true
last_verified: 2026-10-20
---

# Join Linux to Active Directory (realm, SSSD)
> **Created**: 2026-10-20T16:00:00Z
> **Last Modified**: 2026-10-20T16:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> A join writes a machine account to AD and rewrites `sssd.conf`, `krb5.conf`, NSS and PAM. A bad access
> rule can lock every domain user out, and a missing one lets every domain user log on. Test on a lab host
> and keep a local root session open until a domain logon and `sudo` both work.

**Trigger:** Linux servers need domain logons (one password, central disable on leave) instead of local
accounts on every host.

**Goal:** the host is joined, only named AD groups can log on, admin rights come from an AD group,
and the machine keytab is protected and rotated.

| Step | Command | Result |
| :--- | :--- | :--- |
| Find the domain | `realm discover` | DNS SRV, required packages |
| Join | `realm join` | computer account, `/etc/krb5.keytab`, `sssd.conf` |
| Restrict logon | `realm permit -g` or `ad_access_filter` | only listed groups log on |
| Admin rights | `/etc/sudoers.d/` with `%group` | sudo from AD membership |
| Check | `id`, `getent`, `klist -k`, `sssctl` | name lookup, keytab, health |

## 1. Prerequisites: DNS, time, ports

Kerberos fails on name and clock problems before anything else, so check these first.

```bash
# DNS must point at the AD DNS servers and resolve the SRV records
resolvectl status | grep -i 'DNS Servers'
dig +short -t SRV _ldap._tcp.ad.example.com
dig +short -t SRV _kerberos._tcp.ad.example.com

# Time within the Kerberos skew (5 minutes by default) of the DCs
chronyc tracking | grep -E 'Reference ID|System time'
```

Open these from the host to the domain controllers (RHEL 9 AD integration guide): DNS 53, Kerberos 88
and 464, LDAP 389, Global Catalog 3268 (used by `id_provider = ad`), SMB 445 (to read GPOs), NTP 123.
LDAPS 636/3269 is optional.

Install the packages:

```bash
# RHEL 9 / Rocky / Alma
dnf install realmd sssd oddjob oddjob-mkhomedir adcli krb5-workstation samba-common-tools

# Ubuntu 24.04
apt install realmd sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit
```

Do not create a local account with the same name as an AD user; the duplicate breaks logons.

## 2. Discover and join

```bash
realm discover ad.example.com              # realm name, server software, packages still needed
realm join -v -U svc-domainjoin \
    --computer-ou='OU=Linux,OU=Servers,DC=ad,DC=example,DC=com' \
    --os-name="$(. /etc/os-release; echo "$NAME")" --os-version="$(. /etc/os-release; echo "$VERSION_ID")" \
    ad.example.com
realm list                                  # configured: kerberos-member, login-policy
```

- Use a dedicated join account delegated "create/delete computer objects" on the Linux OU, not a
  Domain Admin. Create that OU and delegation on the Windows side first, see
  [Active Directory management](active-directory-domain-management.md).
- `--automatic-id-mapping=no` keeps UID/GID values from AD `uidNumber`/`gidNumber`. Without it SSSD
  computes IDs from the SID (`ldap_id_mapping = true`, the AD provider default). Pick one before the
  first logon; changing it later changes file ownership.
- `--one-time-password` joins with a pre-created computer account instead of a user password.
- On Ubuntu, create home directories at first logon with `pam-auth-update --enable mkhomedir`.

Check from the Windows side:

```powershell
Get-ADComputer -Identity 'web01' -Properties OperatingSystem, OperatingSystemVersion, PasswordLastSet, ServicePrincipalName |
    Select-Object Name, DistinguishedName, OperatingSystem, PasswordLastSet, ServicePrincipalName
```

## 3. Restrict who can log on

After a join, `realm` sets `access_provider = ad`. With that provider SSSD applies the computer's GPO
logon rights (`ad_gpo_access_control = enforcing` is the default), so "Allow log on locally" /
"Allow log on through Remote Desktop Services" in a GPO linked to the Linux OU decide who gets in
(`sshd` and `cockpit` map to the remote-interactive right). If you do not manage that GPO, add one
of the rules below as well.

**Option A: simple allow list by group** (easiest, nested groups work):

```bash
realm permit -g 'linux-web-admins@ad.example.com' 'linux-web-users@ad.example.com'
realm permit -x 'olduser@ad.example.com'      # withdraw one entry
```

This writes `access_provider = simple` with `simple_allow_groups`. sssd-simple(5): once an allow list
is set, everyone not on it is denied; a deny list match beats an allow match; if every list is empty,
everyone is allowed. Local groups are not evaluated.

**Option B: LDAP filter** (any attribute, keep `access_provider = ad`):

```ini
# /etc/sssd/sssd.conf  [domain/ad.example.com]
access_provider = ad
ad_access_filter = (memberOf:1.2.840.113556.1.4.1941:=CN=linux-web-admins,OU=Groups,DC=ad,DC=example,DC=com)
# per domain in a forest:  DOM:child:(memberOf=...)   or   FOREST:EXAMPLE.COM:(memberOf=...)
```

The `1.2.840.113556.1.4.1941` matching rule follows nested groups; plain `memberOf=` does not. Never
leave `access_provider = permit` on a server.

Apply and test:

```bash
chmod 600 /etc/sssd/sssd.conf && chown root:root /etc/sssd/sssd.conf   # sssd refuses other modes
sssctl config-check
systemctl restart sssd
sssctl user-checks 'alice@ad.example.com' -s sshd -a acct              # PAM account phase: allowed or denied
```

## 4. Admin rights from an AD group

Grant sudo to an AD group in a drop-in file (same rules as
[sudo allowlists](delegated-admin-jea-sudo-polkit.md#5-sudo-command-allowlists-done-right)):

```bash
cat > /etc/sudoers.d/60-ad-linux-admins <<'EOF'
# AD group linux-web-admins: full admin on web servers, logged
%linux-web-admins@ad.example.com ALL=(ALL:ALL) ALL
EOF
chmod 0440 /etc/sudoers.d/60-ad-linux-admins
visudo -cf /etc/sudoers.d/60-ad-linux-admins
```

- Match the group name exactly as `id alice@ad.example.com` prints it. With
  `use_fully_qualified_names = False` it is `linux-web-admins`; a group name with spaces must be escaped
  (`%domain\ admins`).
- Keep one local break-glass account in `wheel`/`sudo` for the day the DCs are unreachable.
- Prefer a narrow allowlist over `ALL` for operator groups.

## 5. Machine keytab: protect and rotate

`/etc/krb5.keytab` holds the computer account's keys. Anyone who reads it can act as the host in AD.

```bash
stat -c '%a %U:%G %n' /etc/krb5.keytab          # expect 600 root:root
klist -kte /etc/krb5.keytab                      # principals, KVNO, enctypes (no keys printed)
```

- Expect `HOST/`, `host/` and `RestrictedKrbHost/` principals and AES enctypes. RC4-only entries mean
  the account's `msDS-SupportedEncryptionTypes` needs fixing on the AD side.
- SSSD renews the machine password itself: `ad_maximum_machine_account_password_age` defaults to 30
  days, checked per `ad_machine_account_password_renewal_opts` (default `86400:750:300`). Do not
  disable it.
- A host restored from an old backup has a stale keytab. Rejoin it (`realm leave` then `realm join`)
  or reset with `adcli update --computer-password-lifetime=0`.
- Back up nothing that contains the keytab to a share readable by non-admins.

## 6. Troubleshooting

| Symptom | Check | Usual fix |
| :--- | :--- | :--- |
| `realm discover` finds nothing | `dig -t SRV _ldap._tcp.<domain>` | point DNS at AD, fix search domain |
| `Clock skew too great` | `chronyc tracking` | sync to the DCs or the domain NTP source |
| `id user@domain` returns nothing | `sssctl domain-status ad.example.com` | GC 3268 blocked, offline domain, `ad_server` list |
| User exists but logon denied | `sssctl user-checks user -s sshd`, `journalctl -u sssd` | user not in allow group, GPO logon right |
| Group change not seen | `sss_cache -E` | cached entries; wait or expire the cache |
| Works then stops after weeks | `klist -k`, `adcli testjoin` | stale machine password; rejoin |

```bash
sssctl domain-status ad.example.com      # online, active servers
adcli testjoin                           # exit 0 when the machine account and keytab still work
journalctl -u sssd --since -1h
# Debug for one test, then turn it off again:
sssctl debug-level 6 && sssctl logs-remove
```

Do not remove SSSD's cache (`/var/lib/sss/db`) on a production host while the DCs are unreachable;
cached logons stop working.

## 7. Verify

- [ ] `realm list` shows `login-policy: allow permitted logins` (simple) or the filter is in `sssd.conf`.
- [ ] A user outside the allowed groups is denied (`sssctl user-checks ... -a acct`).
- [ ] `sudo -l -U alice@ad.example.com` lists only what the group should have.
- [ ] `/etc/krb5.keytab` and `/etc/sssd/sssd.conf` are `600 root:root` and watched by
      file integrity monitoring.
- [ ] The AD groups used here are part of the
      [access review](../assurance/effective-permissions-access-review.md).

ATT&CK relevance: domain logons on Linux are **T1078.002** (Valid Accounts: Domain Accounts); a stolen
keytab is used like a stolen credential, so treat it as one.

## Related

- [Active Directory management](active-directory-domain-management.md)
- [Delegated administration (JEA, sudo, polkit)](delegated-admin-jea-sudo-polkit.md)
- [Deploy SSH keys](ssh-key-deployment.md)
- [Run an SSH certificate authority](ssh-certificate-authority.md)
- [Users, groups and privilege](../../fundamentals/concepts/users-groups-permissions.md)

## Sources

- [realm(8)](https://www.freedesktop.org/software/realmd/docs/realm.html)
- [sssd-ad(5)](https://man.archlinux.org/man/sssd-ad.5.en), [sssd-simple(5)](https://linux.die.net/man/5/sssd-simple)
- [SSSD: AD provider](https://sssd.io/docs/ad/ad-provider.html)
- [RHEL 9: Connecting RHEL systems directly to AD using SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/integrating_rhel_systems_directly_with_windows_active_directory/connecting-rhel-systems-directly-to-ad-using-sssd_integrating-rhel-systems-directly-with-active-directory)
