---
title: Credential Rotation After a Compromise
type: workflow
platforms:
  - Active Directory
  - Windows Server
  - Linux
  - Entra ID
  - Azure
languages:
  - PowerShell
  - Bash
  - CMD
tasks:
  - Incident Response
  - Administration
verified: true
last_verified: 2026-10-18
difficulty: advanced
category: Identity
tags:
  - playbook
  - credential rotation
  - krbtgt
  - gmsa
  - service accounts
  - ssh keys
  - api tokens
  - certificates
  - eviction
aliases: [rotate credentials after breach, krbtgt double reset, reset krbtgt twice, golden ticket remediation, krbtgt replication wait, rotate service account password after compromise, gmsa compromised, force gmsa password change, replace gmsa, rotate ssh host keys, revoke ssh user key, ssh krl revoked keys, rotate api token after leak, revoke app registration secret, revoke certificate key compromise, certutil revoke, certbot revoke keycompromise, post-incident credential reset order]
---

# Credential Rotation After a Compromise

**Trigger:** the investigation found that an attacker had Domain Admin or domain controller access, read a service
account password or a gMSA password, copied SSH keys, API tokens or certificate private keys, or you cannot rule
any of that out. Use this playbook after [account compromise](account-compromise.md) or
[compromised service principal](compromised-service-principal.md) containment, when it is time to make every
stolen credential worthless.

!!! warning "Before you run anything"
    Every rotation here can stop production services. Run each command with `-WhatIf` (PowerShell) or in a lab
    first, from a clean admin workstation, inside an approved change window, and keep the change log as incident
    evidence. The commands are compared with Microsoft Learn, the OpenSSH manual pages and the Certbot
    documentation listed under Sources; they have not been run against a live domain or production host.

## Order of operations

Rotating while the attacker still has a foothold only hands them the new credentials. Evict first, then rotate from
the most powerful credential down, and use the krbtgt wait to do the rest:

| Step | What | Why this position |
| --- | --- | --- |
| 0 | **Contain and evict**: isolate hosts, remove persistence, disable rogue accounts ([automated containment](automated-containment.md), [account compromise § Contain](account-compromise.md#7-contain)) | A live implant reads every new secret as soon as you set it |
| 1 | **Inventory dependencies** for every credential on the list (next section) | A rotation without a dependency list is an outage |
| 2 | **Privileged human accounts**: Domain/Enterprise Admins, Tier-0 operators, break-glass | Whoever holds these can read the new krbtgt key and every other secret |
| 3 | **krbtgt reset #1** | Starts the ticket-lifetime clock; forged and stolen TGTs signed with the oldest key stop working |
| 4 | **Service accounts and gMSAs** | Done during the krbtgt wait |
| 5 | **API tokens and app secrets** (Entra app registrations, vault tokens, SaaS keys) | Done during the krbtgt wait |
| 6 | **SSH host and user keys** | Done during the krbtgt wait |
| 7 | **Certificates**: revoke and reissue | Certificates authenticate without the password (PKINIT, client TLS), so a password reset does not end their use |
| 8 | **krbtgt reset #2**, after replication and the ticket lifetime | Removes the last key the attacker might have from the password history |
| 9 | **Verify and monitor**: re-run the audits, watch for use of the old credentials | Proves the old credentials are dead |

Rotate the credentials of an account before you rotate the secrets that account could read: a service account that
can read a Key Vault comes before the vault secrets themselves.

## 1. Dependency check: what uses this credential?

Run the read-only [service account audit](../assurance/service-account-audit.md) scripts on every host that may use
the account, and keep the NDJSON as the "before" snapshot. Both scripts write the same fields (`check`, `target`,
`account`, `details`), so one filter answers "which services and tasks run as this account?".

```powershell
# Windows / AD, elevated, RSAT ActiveDirectory module. -WhatIf first: shows each collection step, reads nothing
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -WhatIf
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -ExportSnapshotPath ".\before-$env:COMPUTERNAME.json" |
    Where-Object { $_.account -like '*svc-app*' -and $_.check -in 'SA-SERVICE-INVENTORY', 'SA-TASK-NAMED-USER', 'SA-SPN-USER', 'SA-GMSA-RETRIEVERS' } |
    Format-Table check, target, account, severity -AutoSize
```

```bash
# Linux, as root. --whatif first: lists the sources, reads nothing
sudo ./scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh --whatif
sudo ./scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh > "before-$(hostname).ndjson"
jq -c 'select(.account == "svc-app" and (.check == "SA-UNIT-USER" or .check == "SA-SUDO-NOPASSWD" or .check == "SA-CREDSTORE-READABLE")) | {check, target, account}' "before-$(hostname).ndjson"
```

With the NDJSON from many hosts in Splunk, one search lists every place an account is used:

```spl
index=assurance tool IN ("FUNC_PS_AUDIT_SERVICE_ACCOUNT", "FUNC_BASH_AUDIT_SERVICE_ACCOUNT") action=audit account="*svc-app*" earliest=-7d
| stats values(target) AS used_by values(check) AS checks latest(_time) AS last_seen BY host account
```

The scripts see services, scheduled tasks, systemd units, sudoers and credential stores. They do not see:

- application config files, connection strings, IIS application pool identities set in `applicationHost.config`,
  scripts with embedded credentials, or other applications' own credential vaults;
- Linux keytabs and SSH `authorized_keys` (listed in [SSH keys](#5-ssh-host-and-user-keys) below);
- where an API token or certificate is deployed. For secrets, the store tells you who reads it:
  [Windows](../administration/windows-service-secrets-storage.md#7-who-can-read-the-secret) ·
  [Linux](../administration/linux-service-secrets-storage.md#6-who-can-read-the-secret).

Add those by hand, with the owner of each application, before the change window. For AD accounts, the logon events
on domain controllers also show where an account authenticates from (event 4624 on member hosts, 4768/4769 on DCs);
see [investigate a user in Splunk](../investigation/investigate-user-splunk.md).

## 2. krbtgt: reset twice, with a wait between

The krbtgt key signs every Kerberos TGT in the domain. An attacker with that key forges tickets (golden ticket,
[T1558.001](https://attack.mitre.org/techniques/T1558/001/)) for any account, including disabled or deleted ones.
Microsoft's forest recovery guide says to reset the password **twice** and to **wait 10 hours** between the resets:
10 hours is the default *Maximum lifetime for user ticket* and *for service ticket*, and the wait must be longer
than whatever your domain has configured. The account keeps the two most recent passwords, so only the second reset
removes the key the attacker had.

### Before reset #1

```powershell
# 1. Replication must be healthy BEFORE you start. Fix every failure first
repadmin /replsummary
repadmin /showrepl * /csv | ConvertFrom-Csv | Where-Object { $_.'Number of Failures' -ne '0' }

# 2. The ticket lifetime you must wait out (Default Domain Policy; check other GPOs linked to the domain too)
$domain = (Get-ADDomain).DNSRoot
Select-String -Path "\\$domain\SYSVOL\$domain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -Pattern 'MaxTicketAge|MaxServiceAge|MaxRenewAge'

# 3. Baseline: password age and key version of krbtgt
Get-ADUser -Identity krbtgt -Properties PasswordLastSet, 'msDS-KeyVersionNumber' |
    Select-Object Name, PasswordLastSet, 'msDS-KeyVersionNumber'
```

`MaxTicketAge` is in hours (default 10), `MaxServiceAge` in minutes (default 600), `MaxRenewAge` in days (default 7).
Your wait is the larger of the first two, plus the time replication needs.

### Reset #1

Reset on the PDC emulator so the change starts in one known place. The password you set does not matter: the
domain controller replaces it with a strong generated one.

```powershell
$pdc = (Get-ADDomain).PDCEmulator
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$newPassword = ConvertTo-SecureString -String ([Convert]::ToBase64String($bytes)) -AsPlainText -Force

Set-ADAccountPassword -Identity krbtgt -Server $pdc -Reset -NewPassword $newPassword -WhatIf
# Remove -WhatIf only inside the approved change window
```

The same reset in the GUI: *Active Directory Users and Computers* → *View* → *Advanced Features* → *Users* →
right-click **krbtgt** → *Reset Password*.

Read-only domain controllers each have their own account, `krbtgt_<number>`. The steps above do not reset them;
if an RODC was compromised, reset its `krbtgt_<number>` account the same way (twice). Do not delete those
accounts.

### Replication check between the resets

```powershell
# Push the change from the PDC to all partners in all sites, then confirm every DC has the same version
repadmin /syncall $pdc /A /e /P /d
repadmin /showobjmeta * "CN=krbtgt,CN=Users,DC=example,DC=test"
repadmin /replsummary
```

In the `/showobjmeta` output, look at the `unicodePwd` and `pwdLastSet` rows: the `Ver` (version) and
`Org.Time/Date` columns must be the same on every domain controller, with the PDC as the originating DC. A DC that
still shows the old version has not replicated: fix it before you continue. Only start counting the wait once every
DC has the new version.

### Reset #2

After every DC shows the first reset **and** the ticket lifetime has passed (default 10 hours), run the same
`Set-ADAccountPassword` again, then the same replication check. Tickets issued before reset #1 are now invalid
everywhere; tickets issued between the resets keep working, because the history still holds the reset #1 key.
Some services may log Kerberos errors until their tickets renew; restart a service only if it does not recover.

### Verify krbtgt

- `msDS-KeyVersionNumber` is two higher than the baseline and `PasswordLastSet` is the time of reset #2, asked of
  each DC: `Get-ADDomainController -Filter * | ForEach-Object { Get-ADUser krbtgt -Server $_.HostName -Properties PasswordLastSet, 'msDS-KeyVersionNumber' }`.
- `repadmin /showobjmeta` shows the same `unicodePwd` version on every DC.
- `repadmin /replsummary` shows no failures.
- Keep hunting for forged tickets after reset #2: [Kerberoasting and ticket hunting](../threat-hunting/kerberoasting-asreproast-hunting.md).

## 3. Service accounts (typed password)

A service that runs as a named domain user has its password in LSA secrets on every host that runs it
([why](../administration/windows-service-accounts-least-privilege.md#1-pick-the-identity)). After a compromise,
rotate it on the account and on every service and task from the dependency list, in the same window.

```powershell
$acct = 'EXAMPLE\svc-app'
$cred = Get-Credential -UserName $acct -Message 'New password for the service account (25+ random characters)'

# 1. AD (dry run first)
Set-ADAccountPassword -Identity 'svc-app' -Reset -NewPassword $cred.Password -WhatIf

# 2. Each service on each host from the dependency list (PowerShell 6.0+ for -Credential)
Set-Service -Name AppSvc -Credential $cred -WhatIf
Restart-Service -Name AppSvc -WhatIf

# 3. Each scheduled task that stores the password. Set-ScheduledTask has no -WhatIf: check the task first
Get-ScheduledTask -TaskName 'Nightly export' | Select-Object TaskPath, TaskName, @{ n = 'User'; e = { $_.Principal.UserId } }
Set-ScheduledTask -TaskName 'Nightly export' -User $acct -Password $cred.GetNetworkCredential().Password
```

Then:

- **Better than a new password**: move the service to a gMSA or a virtual account now, while it is being touched
  ([how](../administration/windows-service-accounts-least-privilege.md#2-create-and-assign-the-account)).
- **SPN accounts**: set AES-only encryption while you are there
  ([Kerberos hardening](../hardening/ad-kerberos-ldap-hardening.md)).
- **Linux hosts with a keytab** for the account need a new keytab after the reset: the old keys in it stop working.
- **Linux local service accounts** have no password to rotate when they are set up as on the
  [Linux least-privilege page](../administration/linux-service-accounts-least-privilege.md) (`nologin`, locked
  password). Rotate the secrets they read instead (section 6).
- **Application secrets** stored for the service (DPAPI blobs, SecretStore, systemd credentials, Vault): rotate them
  with the steps for that store: [Windows](../administration/windows-service-secrets-storage.md#6-rotate-a-service-logon-password) ·
  [Linux](../administration/linux-service-secrets-storage.md#2-systemd-credentials-one-host).

**Verify:**

```powershell
Get-ADUser -Identity 'svc-app' -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
Get-Service -Name AppSvc | Select-Object Name, Status
# Logon failures for the service since the change (7000 = failed to start, 7038 = logon failure)
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7000, 7038; StartTime = (Get-Date).AddHours(-2) } -ErrorAction SilentlyContinue
```

Re-run the audit script: `SA-STALE-PASSWORD` is gone for the account, and the dependency list matches the
before-snapshot (nothing still uses the account that you missed).

## 4. gMSA: replace it, the password cannot be forced

An attacker who could read `msDS-ManagedPassword` (one of the `PrincipalsAllowedToRetrieveManagedPassword`, or
Domain Admin) has the current and previous gMSA password. There is no supported way to force a new one early:

- `Reset-ADServiceAccountPassword` works only for **standalone** MSAs; Microsoft Learn: reset is not supported for
  group managed service accounts.
- The password interval (`ManagedPasswordIntervalInDays`, default 30) can only be set when the gMSA is created.

So the fix is a **new gMSA**, with the retrievers restricted, and the old one removed:

```powershell
# 1. Who could read the old password? (the audit's SA-GMSA-RETRIEVERS finding shows the same)
Get-ADServiceAccount -Identity gmsa-app -Properties PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames |
    Select-Object Name, PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames

# 2. New gMSA; only a group of the hosts that run the service may retrieve its password
New-ADServiceAccount -Name gmsa-app2 -DNSHostName gmsa-app2.example.test `
    -PrincipalsAllowedToRetrieveManagedPassword 'gmsa-app-hosts' -WhatIf

# 3. On each host: install, test, switch the service (account name ends in $, password empty)
Install-ADServiceAccount -Identity gmsa-app2
Test-ADServiceAccount -Identity gmsa-app2
sc.exe config AppSvc obj= 'EXAMPLE\gmsa-app2$'
Restart-Service -Name AppSvc -WhatIf

# 4. Move any SPNs from the old account to the new one (setspn -D, then setspn -S), then remove the old gMSA
Uninstall-ADServiceAccount -Identity gmsa-app   # on each host
Remove-ADServiceAccount -Identity gmsa-app -WhatIf
```

Grant the new gMSA the same file, registry and logon rights as the old one (they are tied to the SID, not the
name): [least privilege steps](../administration/windows-service-accounts-least-privilege.md#3-logon-rights-allow-service-deny-everything-else).

gMSA passwords are computed from the KDS root key. If the attacker had Domain Admin or DC access, assume the root key
was read as well and plan the gMSA replacement as part of forest recovery, not one account at a time. A new root key
(`Add-KdsRootKey`) is not usable on every DC until replication finishes, which Microsoft allows up to 10 hours for;
Microsoft also notes the KDC should be restarted on all DCs if the root key is re-created.

**Verify:**

- `Test-ADServiceAccount -Identity gmsa-app2` returns `True` on every host that runs the service, and `False` on
  hosts that should not.
- Re-run the audit: no `SA-SERVICE-INVENTORY` or `SA-TASK-NAMED-USER` row still names the old gMSA, and
  `SA-GMSA-RETRIEVERS` for the new one is `info`, not `high`.
- `Get-ADServiceAccount -Identity gmsa-app` returns "cannot find an object" once it is removed.

## 5. SSH host and user keys

### Which keys and where

```bash
# Host keys sshd actually uses, and where it reads authorized keys and revoked keys
sudo sshd -T | grep -Ei '^(hostkey|hostcertificate|authorizedkeysfile|revokedkeys|trustedusercakeys) '

# authorized_keys files under the default location (add any AuthorizedKeysFile path from the line above)
sudo find /root /home -name 'authorized_keys*' -type f -exec ls -l {} \;
```

On Windows OpenSSH, administrators' keys are in `C:\ProgramData\ssh\administrators_authorized_keys`
([Windows OpenSSH keys](../administration/ssh-key-deployment.md#target-windows-openssh-server)).

### Host keys

A stolen host private key lets the attacker impersonate the server to every client that trusts it. Replace the keys,
then make clients trust only the new ones.

```bash
# 1. Keep the old keys as evidence, out of /etc/ssh
sudo install -d -m 0700 /root/ssh-hostkeys-old
sudo mv /etc/ssh/ssh_host_* /root/ssh-hostkeys-old/

# 2. Generate new host keys for every default type that is missing (all of them now)
sudo ssh-keygen -A

# 3. Test the config and keys, then reload (unit is "ssh" on Debian/Ubuntu, "sshd" on RHEL family)
sudo sshd -t && sudo systemctl reload ssh

# 4. Publish the new fingerprints through a trusted channel (CMDB, ticket), not over the SSH connection
for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$k"; done
```

On clients and jump hosts, remove the old entry and mark the old key as revoked, so a host still presenting it is
refused even if someone accepts it by mistake:

```bash
ssh-keygen -R server01.example.test                    # removes all keys for the host from known_hosts
ssh-keygen -F server01.example.test                    # nothing left
# In /etc/ssh/ssh_known_hosts (managed globally): @revoked * <old key type> <old base64 key>
```

If you use an SSH CA for host certificates (`HostCertificate`), sign the new host key (`ssh-keygen -s ca -h -I
server01 -n server01.example.test -V +52w ssh_host_ed25519_key.pub`) and, if the **CA** key was stolen, replace the
CA and every `@cert-authority` line that trusts it.

### User keys

```bash
# 1. Remove the stolen public key from every authorized_keys file it is in (match on the base64 part)
sudo grep -rlF 'AAAAC3NzaC1lZDI1NTE5AAAA<old key>' /root/.ssh /home/*/.ssh

# 2. Revoke it for the whole host with a KRL, so it fails even if it is added back somewhere
sudo ssh-keygen -k -f /etc/ssh/revoked_keys old_id_ed25519.pub          # new KRL
sudo ssh-keygen -k -u -f /etc/ssh/revoked_keys another_old_key.pub      # add to the existing KRL
# sshd_config:  RevokedKeys /etc/ssh/revoked_keys
sudo sshd -t && sudo systemctl reload ssh

# 3. The owner makes a new key on a clean device and deploys it
ssh-keygen -t ed25519 -a 100 -C "user@example.test $(date -u +%Y-%m-%d)"
```

`sshd_config(5)`: if the `RevokedKeys` file is not readable, sshd refuses public-key authentication for **all**
users. Check its owner and mode before the reload, and keep a console session open
([zero-lockout checklist](../administration/ssh-key-deployment.md#8-zero-lockout-safe-cutover-checklist)).

Service keys (deploy keys, automation accounts) go through the same steps; pin the new key with `from="..."` and a
forced command where the [key lockdown](../administration/ssh-key-deployment.md#7-key-lockdown-automation-privileges)
page shows how.

**Verify:**

```bash
ssh-keygen -Q -f /etc/ssh/revoked_keys old_id_ed25519.pub   # reports the key as REVOKED
ssh-keyscan -t ed25519 server01.example.test | ssh-keygen -lf -   # matches the new published fingerprint
```

And from a client: login with the old user key fails, login with the new key works, and the client warns or refuses
if it is still shown an old host key.

## 6. API tokens and application secrets

The order is the same for every token, so the service never runs on a revoked token:

1. **Find every copy**: the store it lives in ([Windows](../administration/windows-service-secrets-storage.md#pick-a-store) ·
   [Linux](../administration/linux-service-secrets-storage.md#pick-a-store)), CI/CD variables, config files from the
   dependency check.
2. **Issue a new token** with the narrowest scope and a short expiry.
3. **Deploy** the new token to the store, restart or reload the consumers.
4. **Revoke the old token** at the issuer. Deleting it from your store is not revoking it.
5. **Verify**: the old token is refused, the service works, and the issuer's logs show no use of the old token after
   the revocation time.

Entra ID application secret (the containment steps are in
[compromised service principal](compromised-service-principal.md)):

```powershell
Connect-MgGraph -Scopes 'Application.ReadWrite.All'
$appId = '<APP_OBJECT_ID>'

# Current secrets: KeyId, name, hint (first characters), expiry
(Get-MgApplication -ApplicationId $appId -Property passwordCredentials).PasswordCredentials |
    Select-Object KeyId, DisplayName, Hint, EndDateTime

# 1. New secret, 90 days; SecretText is shown once: put it straight into the vault
$new = Add-MgApplicationPassword -ApplicationId $appId -PasswordCredential @{
    displayName = 'rotated-after-incident'; endDateTime = (Get-Date).ToUniversalTime().AddDays(90) }

# 2. After the consumers use the new secret: remove the old one by KeyId
Remove-MgApplicationPassword -ApplicationId $appId -KeyId '<OLD_KEY_ID>' -WhatIf
```

Prefer a managed identity or workload identity federation over a new secret where the workload supports it: then
there is no secret left to steal.

Other stores: [Azure Key Vault](../../platforms/azure/keys-secrets.md#4-create-rotate-and-disable-change) ·
[AWS](../../platforms/aws/keys-secrets.md) · [GCP](../../platforms/gcp/keys-secrets.md) ·
[HashiCorp Vault / OpenBao](../administration/linux-service-secrets-storage.md#5-hashicorp-vault-openbao-many-hosts) ·
[SOPS + age](../administration/linux-service-secrets-storage.md#4-sops-age-encrypted-files-in-git).
GitHub tokens, SSH/deploy keys and Actions secrets: [GitHub incident response](../../platforms/github/incident-response.md#1-a-token-leaked-identify-and-revoke)
(revoke by token prefix, find what the token did, purge it from Git history). Other SaaS tokens (ticketing, monitoring):
revoke them in that vendor's console or API with the same five steps.

**Verify:** a request with the old token returns 401/403; `Get-MgApplication` lists only the new `KeyId`; the
service principal sign-in logs show no sign-ins with the old credential after the removal.

## 7. Certificates: revoke and reissue

Replace any certificate whose private key was on a compromised host or was exported. A certificate issued to a
compromised account can also be used to sign in as that account (PKINIT, [T1649](https://attack.mitre.org/techniques/T1649/))
after its password has been reset, so revoke those as well.

### AD CS (enterprise CA)

```cmd
:: 1. Certificates the CA issued to the compromised account (Disposition 20 = issued)
certutil -restrict "Disposition=20,RequesterName=EXAMPLE\svc-app" -out "RequestID,SerialNumber,NotAfter,CommonName,CertificateTemplate" -view

:: 2. Revoke by serial number with reason 1 (key compromise), then publish a new CRL at once
certutil -revoke <SerialNumber> 1
certutil -CRL
```

Reason `1` (`CRL_REASON_KEY_COMPROMISE`) is the right code when the key may be in the attacker's hands; `4`
(superseded) is for planned replacement. Clients that cached the old CRL only see the revocation once that CRL
expires, unless they use OCSP: shorten the window by publishing the CRL and, where possible, a delta CRL.

If the **CA's own key** may have been taken, revoking leaf certificates is not enough: the attacker can sign new
ones. That is a CA rebuild, planned with the [PKI management](../administration/certificate-and-pki-management.md)
owners.

### Public CA (ACME / Certbot)

```bash
sudo certbot revoke --cert-name www.example.test --reason keycompromise --delete-after-revoke
# New key and certificate: test against the staging server, then for real
sudo certbot certonly --dry-run -d www.example.test
sudo certbot certonly --force-renewal -d www.example.test
```

Without `--delete-after-revoke`, Certbot tries to renew the revoked certificate on the next `certbot renew`.
Generate a **new private key** for every reissued certificate; a renewal that reuses the old key leaves the attacker's
copy valid. For manual CSRs see [TLS certificate deployment](../administration/tls-certificate-deployment.md).

**Verify:**

```bash
# The service presents the new certificate (new serial, new expiry)
openssl s_client -connect www.example.test:443 -servername www.example.test </dev/null 2>/dev/null |
    openssl x509 -noout -serial -enddate -fingerprint -sha256
```

```cmd
:: AD CS: the old serial is in the revoked view; chain check of the old certificate fetches the CRL and fails
certutil -restrict "SerialNumber=<SerialNumber>" -out "SerialNumber,RevokedReason,RevokedWhen" -view Revoked
certutil -verify -urlfetch old-cert.cer
```

## 8. Verify and close

- Re-run both audit scripts on the same hosts and compare with the before-snapshots
  (`-InputPath` lets the PowerShell script analyse a saved snapshot again): every account on the rotation list has a
  new `password_age_days`, no service or task still runs as a replaced gMSA, no new `high` finding appeared.
- Keep the detections on for the old credentials for at least the longest ticket, CRL and token lifetime involved:
  logons with the replaced accounts, the revoked SSH key, the removed app secret `KeyId`.
- Record in the incident log what was rotated, when, by whom, and the verify output for each.

## Related

- [Account compromise](account-compromise.md) · [Compromised service principal](compromised-service-principal.md) · [Automated containment](automated-containment.md)
- [Windows service accounts with least privilege](../administration/windows-service-accounts-least-privilege.md) · [Linux service accounts with least privilege](../administration/linux-service-accounts-least-privilege.md)
- [Windows service secrets](../administration/windows-service-secrets-storage.md) · [Linux service secrets](../administration/linux-service-secrets-storage.md)
- [Service account audit](../assurance/service-account-audit.md) · [AD Kerberos & LDAP hardening](../hardening/ad-kerberos-ldap-hardening.md)
- [GitHub incident response](../../platforms/github/incident-response.md) · [GitHub Actions secrets & OIDC](../../platforms/github/keys-secrets.md)
- [SSH key deployment](../administration/ssh-key-deployment.md) · [Certificate and PKI management](../administration/certificate-and-pki-management.md) · [Kerberos](../../fundamentals/kerberos.md)

## Sources

- Microsoft Learn — [AD Forest Recovery: reset the krbtgt password](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password) (reset twice, 10-hour wait, password history of 2, RODC `krbtgt_<number>`) · [Maximum lifetime for user ticket](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket) · [Set-ADAccountPassword](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountpassword)
- Microsoft Learn — [repadmin](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc770963(v=ws.11)) · [repadmin /syncall](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc835086(v=ws.11)) · [repadmin /showobjmeta](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742104(v=ws.11))
- Microsoft Learn — [Manage group managed service accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts) (interval set only at creation, Install/Test/Uninstall-ADServiceAccount) · [Reset-ADServiceAccountPassword](https://learn.microsoft.com/powershell/module/activedirectory/reset-adserviceaccountpassword) (not supported for gMSA) · [Create the KDS root key](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key)
- Microsoft Learn — [Set-Service](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-service) · [Set-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/set-scheduledtask) · [Add-MgApplicationPassword](https://learn.microsoft.com/powershell/module/microsoft.graph.applications/add-mgapplicationpassword) · [Remove-MgApplicationPassword](https://learn.microsoft.com/powershell/module/microsoft.graph.applications/remove-mgapplicationpassword) · [certutil](https://learn.microsoft.com/windows-server/administration/windows-commands/certutil) (`-revoke` reason codes, `-CRL`, `-view`, `-verify -urlfetch`)
- OpenSSH manual pages — [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen) (`-A`, `-R`, `-F`, `-l`, `-k`, `-u`, `-Q`, `-s`, `-h`) · [sshd_config(5)](https://man.openbsd.org/sshd_config) (`HostKey`, `RevokedKeys`, `AuthorizedKeysFile`, `HostCertificate`) · [sshd(8)](https://man.openbsd.org/sshd) (`-t`, `-T`, `@revoked`, `@cert-authority`)
- Certbot — [User guide: revoking and renewing certificates](https://eff-certbot.readthedocs.io/en/stable/using.html) (`revoke --reason`, `--delete-after-revoke`, `--force-renewal`, `--dry-run`)
- MITRE ATT&CK — [T1558.001](https://attack.mitre.org/techniques/T1558/001/) · [T1558.003](https://attack.mitre.org/techniques/T1558/003/) · [T1552.004](https://attack.mitre.org/techniques/T1552/004/) · [T1528](https://attack.mitre.org/techniques/T1528/) · [T1649](https://attack.mitre.org/techniques/T1649/) · [T1098.004](https://attack.mitre.org/techniques/T1098/004/)
