---
title: Encrypt Linux Disks with LUKS2 (TPM2, Clevis/Tang, Key Slots, Header Backup)
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Administration, Hardening]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [luks, luks2, cryptsetup, disk-encryption, tpm2, clevis, tang, nbde, key-rotation, recovery, data-at-rest]
aliases: [linux full disk encryption, cryptsetup luksFormat, cryptsetup luksAddKey, cryptsetup luksKillSlot, cryptsetup luksRemoveKey, cryptsetup luksHeaderBackup, cryptsetup luksHeaderRestore, cryptsetup luksDump, cryptsetup reencrypt, cryptsetup luksErase, systemd-cryptenroll tpm2, systemd-cryptenroll recovery key, crypttab tpm2-device, clevis luks bind, clevis luks list, clevis luks unbind, clevis luks regen, tang server, network bound disk encryption, linux bitlocker equivalent]
difficulty: advanced
verified: true
last_verified: 2026-10-20
---

# Encrypt Linux Disks with LUKS2 (TPM2, Clevis/Tang, Key Slots, Header Backup)
> **Created**: 2026-10-20T19:45:00Z
> **Last Modified**: 2026-10-20T19:45:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> `cryptsetup luksFormat` destroys all data on the device. `luksKillSlot`, `luksErase` and
> `--wipe-slot` remove unlock methods with no undo; if the last working key goes, the data is gone.
> Before any key-slot change: back up the header (section 5), confirm a second unlock method works,
> and check the device name twice (`lsblk -f`). Practise on a loop device or a test VM first.

**Trigger:** a Linux laptop, server or data volume holds sensitive data unencrypted, or encrypted
volumes have unknown passphrases, no recovery key and no header backup.

**Goal:** every data-bearing volume is LUKS2, unlocks without typing a password where that is safe
(TPM2 or Tang), has an escrowed recovery key, and its keys can be rotated or revoked. This is the
Linux counterpart of [BitLocker key retrieval and status](bitlocker-recovery.md).

| BitLocker | LUKS2 |
| :--- | :--- |
| TPM protector | `systemd-cryptenroll --tpm2-device` or `clevis luks bind ... tpm2` |
| Recovery password (escrowed in AD/Entra) | `systemd-cryptenroll --recovery-key`, stored in your vault |
| Network Unlock | Clevis + Tang (network-bound disk encryption) |
| `manage-bde -protectors -delete` | `luksKillSlot` / `--wipe-slot` |
| `manage-bde -status` | `cryptsetup luksDump`, `lsblk -f` |

## 1. Inventory

```bash
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINTS            # FSTYPE crypto_LUKS = encrypted container
cryptsetup isLuks -v /dev/nvme0n1p3               # exit 0 if LUKS
cryptsetup luksDump /dev/nvme0n1p3                # Version: 2, Keyslots, Tokens, cipher, PBKDF
cat /etc/crypttab                                  # name, device, key file, options
```

In `luksDump`, check: `Version: 2` (LUKS1 has no tokens and no Argon2), cipher `aes-xts-plain64`,
PBKDF `argon2id`, how many keyslots are in use, and which **tokens** (systemd-tpm2, clevis) point to
them. Every keyslot is a working key; one you cannot account for is a finding.

## 2. Create a LUKS2 volume (new disk)

```bash
dev=/dev/sdb                                       # check twice: this wipes the device
cryptsetup luksFormat --type luks2 --pbkdf argon2id "$dev"
cryptsetup open "$dev" data                        # -> /dev/mapper/data
mkfs.ext4 /dev/mapper/data
mkdir -p /srv/data && mount /dev/mapper/data /srv/data

uuid=$(cryptsetup luksUUID "$dev")
echo "data UUID=$uuid none luks,discard" >> /etc/crypttab
echo "/dev/mapper/data /srv/data ext4 defaults 0 2" >> /etc/fstab
```

- Root-disk encryption is easiest at OS install time (installer option "encrypt disk"). Converting a
  running root volume in place is possible with `cryptsetup reencrypt --encrypt` but needs free
  space for the header and a tested backup; reinstalling is usually safer.
- `discard` passes TRIM through; it reveals which blocks are unused. Leave it off if that matters.

## 3. Unlock with TPM2 (systemd-cryptenroll)

Needs systemd 248+ and a TPM 2.0. The TPM releases the key only when the measured boot state
(PCRs) matches what it was at enrollment.

```bash
systemd-cryptenroll --tpm2-device=list
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/nvme0n1p3            # bind to Secure Boot state
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 --tpm2-with-pin=yes /dev/nvme0n1p3   # TPM + PIN (stronger)
```

Then tell the boot to use it, and rebuild the initramfs:

```text
# /etc/crypttab
root UUID=<luks-uuid> none tpm2-device=auto,discard
```

```bash
dracut -f --regenerate-all          # Fedora/RHEL;  Debian/Ubuntu: update-initramfs -u -k all
```

- Without `--tpm2-pcrs` the key is bound to **no** PCRs, so anyone who boots any OS on the machine
  can unseal it. Always pass at least PCR 7.
- A firmware or Secure Boot key update changes PCR 7 and the TPM refuses; the recovery key
  (section 4) gets you in, then wipe and re-enroll: `systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7 <dev>`.
- TPM-only unlock protects a powered-off, stolen disk. It does not protect a stolen laptop that boots
  to a login screen; use `--tpm2-with-pin=yes` for laptops.

## 4. Recovery key and escrow

```bash
systemd-cryptenroll --recovery-key /dev/nvme0n1p3
```

The tool prints a generated high-entropy key once. Store it in your password vault or secrets
manager under the host name and LUKS UUID ([Linux service secrets](linux-service-secrets-storage.md)
covers vault options); never in the ticket or on the same disk. Test it once with
`cryptsetup open --test-passphrase /dev/nvme0n1p3`.

## 5. Header backup

The LUKS header holds the keyslots. If it is damaged, every key is useless. Back it up after every
keyslot change and store it with the recovery key, **not** on the encrypted disk.

```bash
cryptsetup luksHeaderBackup /dev/nvme0n1p3 --header-backup-file "/root/$(hostname)-nvme0n1p3.luksheader"
# copy off the host, then remove the local copy
cryptsetup luksHeaderRestore /dev/nvme0n1p3 --header-backup-file host-nvme0n1p3.luksheader   # recovery only
```

A header backup contains the keyslots as they were: a passphrase you later removed still opens the
disk with the old header. Protect old backups like keys, and replace them after a revocation.

## 6. Network-bound unlock (Clevis + Tang)

Servers in a data centre unlock at boot only while they can reach a Tang server on the internal
network; a disk or server carried out of the building does not unlock.

```bash
# Tang server (dedicated, internal only)
dnf install tang && systemctl enable --now tangd.socket          # listens on TCP 80
tang-show-keys                                                     # thumbprint to verify on clients

# Client
dnf install clevis clevis-luks clevis-dracut                      # Debian/Ubuntu: clevis clevis-luks clevis-initramfs
clevis luks bind -d /dev/sda3 tang '{"url":"http://tang1.example.internal"}'
clevis luks bind -d /dev/sda3 tpm2 '{"pcr_ids":"7"}'              # optional: TPM2 pin
clevis luks bind -d /dev/sda3 sss '{"t":2,"pins":{"tang":[{"url":"http://tang1.example.internal"}],"tpm2":{"pcr_ids":"7"}}}'
clevis luks list -d /dev/sda3                                      # slot -> pin and config
dracut -f --regenerate-all                                         # initramfs needs network: add rd.neednet=1 to the kernel command line
```

- `clevis luks bind` asks for an existing passphrase and the Tang key thumbprint; compare it with
  `tang-show-keys` on the server. Do not script `-y` (trust without checking) in production.
- The `sss` pin with `t:2` above needs **both** Tang and the TPM: the disk must be in this machine
  *and* on this network. `t:1` with two Tang URLs gives Tang high availability.
- Rotate Tang keys (`/usr/libexec/tangd-rotate-keys -d /var/db/tang` or the distro's equivalent),
  run `clevis luks regen -d /dev/sda3 -s <slot>` on each client, then remove the old key files on
  the server once every client is regenerated.

## 7. Rotate and revoke keys

```bash
cryptsetup luksDump /dev/sda3 | sed -n '/^Keyslots:/,/^Tokens:/p'   # which slots exist
cryptsetup luksAddKey /dev/sda3                                    # asks an existing key, then the new one
cryptsetup open --test-passphrase --key-slot 1 /dev/sda3           # which slot does this passphrase open?
cryptsetup luksKillSlot /dev/sda3 0                                # remove slot 0 (asks a key from another slot)
cryptsetup luksRemoveKey /dev/sda3                                 # remove the slot that matches the typed passphrase
systemd-cryptenroll /dev/sda3 --wipe-slot=password                 # remove all plain password slots (after TPM2/recovery work)
clevis luks unbind -d /dev/sda3 -s 2                               # remove a clevis slot and its token
```

- When an admin who knew a passphrase leaves, or a recovery key was exposed: add a new key, remove
  the old slot, take a **new header backup**, destroy old header backups.
- Removing a passphrase does not change the **volume key**. If the volume key itself may be exposed
  (someone had root on the unlocked system, or an old header backup leaked), re-encrypt with a new
  volume key: `cryptsetup reencrypt /dev/sda3` (LUKS2, online, slow; take a backup first).
- Decommissioning: `cryptsetup luksErase /dev/sda3` wipes all keyslots (crypto-erase); the data is
  unreadable unless a header backup exists. Destroy those too.

## 8. Verify

- [ ] `lsblk -f` shows `crypto_LUKS` under every data-bearing partition, swap included.
- [ ] `cryptsetup luksDump` shows `Version: 2`, `argon2id`, and only keyslots you can name (TPM2,
      clevis, recovery, maybe one admin passphrase).
- [ ] The machine reboots unattended (TPM2 or Tang) and still unlocks with the recovery key alone
      (`cryptsetup open --test-passphrase`).
- [ ] With the Tang server unreachable (or PCR 7 changed in a test VM), the boot stops at the
      passphrase prompt instead of unlocking.
- [ ] The recovery key and a current header backup are in the vault, recorded against host name and
      LUKS UUID.

ATT&CK relevance: disk encryption defeats offline access to data and credentials on stolen or
discarded disks (**T1005** data from local system, **T1003.008** `/etc/shadow`, **T1552.004** private
keys) and **T1006** direct volume access from another OS. Unexpected `luksKillSlot`/`luksErase`
on production hosts is a destructive-impact signal (**T1485**, **T1561**).

## Related

- [BitLocker key retrieval and status](bitlocker-recovery.md)
- [Store service secrets and keys on Linux](linux-service-secrets-storage.md)
- [Cryptography fundamentals](../../fundamentals/concepts/cryptography-fundamentals.md)
- [NIST CSF 2.0 (PR.DS-01)](../../fundamentals/grc/nist-csf-2.md)
- [Linux CIS filesystems and services](../hardening/linux-cis-filesystem-services.md)

## Sources

- [cryptsetup(8)](https://man7.org/linux/man-pages/man8/cryptsetup.8.html)
- [systemd-cryptenroll(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
- [crypttab(5)](https://www.freedesktop.org/software/systemd/man/latest/crypttab.html)
- [clevis-luks-bind(1)](https://github.com/latchset/clevis/blob/master/src/luks/clevis-luks-bind.1.adoc)
- [Clevis README](https://github.com/latchset/clevis/blob/master/README.md) · [Tang](https://github.com/latchset/tang)
- [RHEL: Configuring automated unlocking of encrypted volumes (NBDE)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/configuring-automated-unlocking-of-encrypted-volumes-using-policy-based-decryption_security-hardening)
