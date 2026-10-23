---
title: Assess a Wi-Fi Network's Posture — Survey, Encryption and Rogue-AP Awareness
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Network
author: RJGProjectz
date_created: 2026-10-23
last_updated: 2026-10-23
tags: [wifi, wireless, 802-11, wlan, site-survey, airmon-ng, airodump-ng, kismet, monitor-mode, wpa2, wpa3, wep, wps, pmf, management-frame-protection, evil-twin, rogue-ap, deauth, pmkid, handshake, rf-survey, parrot-os, kali]
aliases: [wifi assessment, wireless assessment, wifi survey, wireless site survey, airodump-ng survey, airmon-ng monitor mode, kismet discovery, enumerate wireless networks, assess wpa2 wpa3, wps enabled, pmf management frame protection, rogue ap detection, evil twin detection, wifi encryption audit]
difficulty: intermediate
verified: false
---

# Assess a Wi-Fi Network's Posture — Survey, Encryption and Rogue-AP Awareness
> **Created**: 2026-10-23T00:00:00Z
> **Last Modified**: 2026-10-23T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Radio is shared and borderless, and the law treats it that way.
> 1. Survey and assess **only** the wireless networks named in a signed engagement or that you own and
>    operate. A capture radio hears **every** nearby network — neighbours, tenants, passers-by — and you
>    are authorized for exactly the BSSIDs/SSIDs in scope. Record them in §0 and ignore the rest.
> 2. **Passive first.** Monitor-mode survey (§1–§2) only *listens*; it transmits nothing and is the
>    whole of what this page executes. The active techniques in §3 (deauth, handshake/PMKID capture,
>    offline cracking) are documented as **know-it + detect/harden only** — do **not** run them against a
>    third party, and run them in a lab only when the engagement explicitly authorizes active RF work.
> 3. **RF regulatory + privacy.** Monitor mode and channel hopping can touch frequencies your regulatory
>    domain restricts; set your country (`iw reg set`) and stay on permitted channels. Capturing frames
>    is capturing other people's traffic — collect only in-scope management/beacon data, store it as
>    evidence, and never decrypt or inspect third-party payloads. See
>    [Cyber Law](../fundamentals/concepts/cyber-law.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (aircrack-ng suite, Kismet; Parrot OS /
    Kali packages) but have not been lab-run for this page, and wireless behaviour depends heavily on
    your adapter, driver and regulatory domain. Confirm flags against each tool's `--help`/man page and
    confirm your adapter supports monitor mode in your build. Remove this block when `verified: true`.

**Trigger:** an authorized engagement includes the **wireless** attack surface — a corporate WLAN, a
guest network, an OT/IoT SSID — and you need to inventory what is broadcasting, how it is encrypted, and
whether its posture (legacy encryption, WPS, missing management-frame protection, rogue/evil-twin risk)
would let an attacker in. The wired network map stops at the switch port; Wi-Fi extends the perimeter
into the car park.

**Goal:** produce an evidenced inventory of the in-scope wireless estate — APs and their BSSIDs,
channels and bands, associated clients, and the **encryption and posture** of each network (WEP / WPA2 /
WPA3 / WPS / PMF) — using **passive, listen-only** survey, and understand (for detection and hardening,
not execution) how the weaponized attacks against those weaknesses work. This page is part of Stage 1
(Reconnaissance) of the [red-team lifecycle](index.md); it is the wireless peer of
[Network & Infrastructure Enumeration](network-infrastructure-enumeration.md), and once you associate to
an in-scope network it hands off to that page for the internal sweep. For the theory, see
[Wi-Fi Security (WEP, WPA, WPA2, WPA3)](../fundamentals/concepts/wifi-security.md).

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Enable monitor mode | `iw`, `airmon-ng` | A listen-only capture interface; interfering processes cleared |
| AP / client survey (passive) | `airodump-ng`, `kismet` | BSSIDs, SSIDs, channels, bands, clients, signal |
| Encryption & posture | `airodump-ng` fields, `wash` | WEP/WPA2/WPA3, cipher/auth, WPS state, PMF |
| Rogue-AP / evil-twin awareness | survey deltas vs. an authorized baseline | Unexpected BSSIDs for a known SSID, signal anomalies |
| *Weaponized (know-it only)* | *deauth, handshake/PMKID capture, `hashcat`/`aircrack-ng`* | *How WPA2-PSK fails offline — documented for detect/harden, not run here* |

## 0. Set the scope and the radio once

```bash
# In-scope targets ONLY — fill from the engagement. A survey hears everything; you assess only these.
IFACE="wlan0"                       # the capture-capable adapter
SCOPE_SSID="REPLACE-Authorized-SSID"
SCOPE_BSSID="AA:BB:CC:DD:EE:FF"     # the in-scope AP's MAC
OUT="./wifi_assessment_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
printf '%s %s\n' "$SCOPE_BSSID" "$SCOPE_SSID" > "$OUT/in_scope.txt"

# Set the regulatory domain so channel hopping stays legal for your country.
sudo iw reg set US                  # REPLACE with your two-letter domain
iw reg get
```

## 1. Enable monitor mode (listen-only)

Monitor mode lets the adapter receive **all** 802.11 frames — beacons, probes, management — without
associating or transmitting. `airmon-ng check kill` stops NetworkManager/wpa_supplicant, which otherwise
drag the radio back onto a managed channel:

```bash
# See which processes will fight the radio, then stop them
sudo airmon-ng check
sudo airmon-ng check kill

# Put the adapter into monitor mode (creates e.g. wlan0mon)
sudo airmon-ng start "$IFACE"
iw dev                              # confirm the mon interface + "type monitor"
MON="${IFACE}mon"                   # adjust to whatever airmon-ng reported
```

If `airmon-ng` is not available, `iw` does the same by hand:

```bash
sudo ip link set "$IFACE" down
sudo iw "$IFACE" set monitor control
sudo ip link set "$IFACE" up
MON="$IFACE"
```

A radio that will not enter monitor mode is an adapter/driver limitation, not a target finding — note it
and use a known-good external adapter.

## 2. Passive survey — inventory the air

This is the core of the assessment and the **only part this page executes**: a listen-only sweep that
records every AP and client in range. Scope discipline is everything here — you *see* every network but
*assess* only the in-scope ones.

```bash
# Full passive survey across all channels; write every format for evidence.
# --band abg hops 2.4/5/6 GHz if the adapter supports it. Ctrl-C to stop.
sudo airodump-ng --band abg -w "$OUT/survey" --output-format pcap,csv,kismet "$MON"
```

The live table is the inventory: **BSSID** (AP MAC), **PWR** (signal), **CH** (channel), **ENC / CIPHER
/ AUTH** (encryption posture), **ESSID** (network name) and, below, the associated **STATION** MACs.
Export is already written to `"$OUT"`. [Kismet](https://www.kismetwireless.net/) is the richer
alternative — it discovers passively, tracks clients over time, and flags anomalies:

```bash
sudo kismet -c "$MON"               # then browse http://localhost:2501 for devices/SSIDs/alerts
```

Once you know the in-scope AP's channel, **lock to it** to capture that network cleanly instead of
hopping — still passive:

```bash
sudo airodump-ng -c 6 --bssid "$SCOPE_BSSID" -w "$OUT/scope_ap" "$MON"
```

## 3. Encryption and posture assessment

Turn the survey into a posture verdict per in-scope network. The `airodump-ng` CSV already carries the
fields; read them rather than re-capturing:

- **Encryption (ENC):** `OPN` (open — no encryption, a finding), `WEP` (broken, a critical finding),
  `WPA`/`WPA2`, or `WPA3`. `CIPHER`/`AUTH` tell you `CCMP` vs `TKIP` and `PSK` vs `MGT` (802.1X/EAP).
- **WPS:** often left on and is a well-known weakness. `wash` lists APs with WPS enabled, passively:

```bash
sudo wash -i "$MON"                 # WPS state (and locked/unlocked) per BSSID — listen-only
```

- **Management-Frame Protection (PMF / 802.11w):** required by WPA3, optional on WPA2. Without PMF, the
  deauth in §4a works; with it, management frames are authenticated. The beacon's RSN capabilities show
  whether PMF is required/capable — confirm from the captured beacon in Wireshark
  (`wlan.rsn.capabilities.mfpr`).

Record, per in-scope BSSID: encryption + cipher + auth, WPS on/off, PMF required/capable/absent, band and
channel. That table **is** the wireless finding set; map each weakness to its fix in §Related.

### Rogue-AP / evil-twin awareness (detection, not attack)

An **evil twin** is a rogue AP broadcasting a legitimate SSID to lure clients. Assessing *exposure* to it
is passive: compare the survey against an authorized baseline and flag anomalies —

- the same `ESSID` advertised by a **BSSID you do not own**,
- an unexpectedly **strong signal** for a known SSID (an AP closer than any sanctioned one),
- a known corporate SSID appearing as **open/WEP** when it should be WPA2-Enterprise.

These are findings about the target's **susceptibility**; standing up a rogue AP to prove it is an active
operation for a scoped engagement, and its mechanics live in
[Wi-Fi Deauthentication and Rogue Access Points](../fundamentals/concepts/wifi-deauth-rogue-ap.md).

## 4. Weaponized attacks — *know it, detect it, harden it (not run here)*

The survey above establishes *posture*. The attacks that **exploit** weak posture are documented here
only so you can recognise, detect and defend against them — this project is enumeration/assessment-only,
so no deauth, capture or cracking is executed against a third party. Run them only in a lab the
engagement authorizes.

- **4a. Deauthentication:** forged deauth frames knock a client off an unprotected (no-PMF) network,
  causing a reconnection — the noise a handshake capture or evil-twin lure rides on. PMF (WPA3, or WPA2
  with 802.11w) authenticates management frames and defeats it. Mechanics and defense:
  [Wi-Fi Deauthentication and Rogue Access Points](../fundamentals/concepts/wifi-deauth-rogue-ap.md).
- **4b. Handshake / PMKID capture:** the WPA2-PSK 4-way handshake (or a single PMKID frame from the AP)
  contains material an attacker takes **offline**. Capturing it needs a client reconnection (hence 4a);
  the result is a hash, not a password.
- **4c. Offline cracking:** `hashcat` / `aircrack-ng` guess the passphrase against the captured hash —
  entirely offline, bounded only by passphrase strength and wordlist. This is why a long, random WPA2-PSK
  (or WPA3's SAE, which resists offline guessing) is the control. The passphrase-attack chain and its
  defenses: [WPA/WPA2 Passphrase Attacks (Handshake Capture)](../fundamentals/concepts/wifi-passphrase-attacks.md)
  and [Password Attacks](../fundamentals/concepts/password-attacks.md).

The takeaway for a posture assessment: **WPS enabled, no PMF, or a weak/legacy encryption mode means the
offline chain above is viable** — report it on that basis without running the chain.

## 5. Tear down and consolidate

```bash
# Return the radio to managed mode and restart normal networking
sudo airmon-ng stop "$MON"
sudo systemctl restart NetworkManager

# One evidenced inventory per in-scope network
{
  echo "# Wireless posture inventory  ($(date -u +%FT%TZ))"
  echo "## In-scope APs (BSSID, ENC/CIPHER/AUTH, WPS, PMF, CH/band)"
  # Pull the AP rows from the airodump CSV (first section, before the station list)
  awk 'BEGIN{FS=","} /Station MAC/{exit} NR>1 && NF>8 {print}' "$OUT"/survey-*.csv 2>/dev/null
} > "$OUT/inventory.md"
```

Keep the raw `pcap`/`csv`/Kismet output under `"$OUT"` as evidence. Associated, authorized networks hand
off to [Network & Infrastructure Enumeration](network-infrastructure-enumeration.md) for the internal
sweep; the posture findings feed the reporting phase in
[Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md).

## Detect it

A passive survey (§1–§2) transmits nothing and is, by design, **not** detectable — which is exactly why
wireless defense is about posture and WIDS, not alarming on the listener. The **active** techniques in §4
are loud, and the same events drive detection content on the [Detection](../detection/index.md) tab:

| Offensive technique | Detect it with |
| :--- | :--- |
| Deauthentication flood (§4a) — a burst of deauth/disassoc management frames | [Sigma — Wi-Fi (WLAN-AutoConfig and Unknown Devices)](../detection/sigma/wlan-events.md) · [Sigma — Network Flood (DoS/DDoS)](../detection/sigma/dos-flood.md) |
| Rogue AP / evil twin (§3) — a known SSID on an unauthorized BSSID, client roaming to it | [Sigma — Wi-Fi (WLAN-AutoConfig and Unknown Devices)](../detection/sigma/wlan-events.md) |
| Client association to an unexpected AP / unmanaged device joining | [Sigma — Unmanaged Mobile Access to Corporate Apps](../detection/sigma/unmanaged-mobile-access.md) |

A passive survey leaves no trace; a deauth or evil-twin **does** — a WIDS/WIPS and the WLAN event rules
above are what turn an attacker's active step into an alert.

## Notes

- **Passive is the whole job here.** Monitor-mode survey listens only. Everything in §4 is documented for
  awareness/detection/hardening and is run — if at all — only in an engagement-authorized lab.
- **You hear everything; you assess only the scope.** A capture radio receives every nearby network.
  Authorization is per-BSSID/SSID (`in_scope.txt`), not "whatever is in range" — this is the single
  easiest way to break scope on a wireless engagement.
- **Posture, not payload.** WPS enabled, missing PMF, or WEP/WPA-TKIP are reportable findings on their own
  — they make the offline chain viable; you do not need to run the chain to prove the exposure.
- **Adapter and regulatory domain decide what you can do.** Monitor mode and 5/6 GHz capture depend on the
  chipset/driver; channel availability depends on `iw reg set`. A capability gap is an equipment note, not
  a target finding.
- **Privacy.** Captured frames are other people's traffic — collect only in-scope management/beacon data,
  store it as evidence, and never decrypt or inspect third-party payloads.
- Install notes: `aircrack-ng` (provides `airmon-ng`/`airodump-ng`/`aircrack-ng`), `iw`, `wash` (reaver)
  and `hashcat` ship on or `apt install` onto Parrot/Kali; `kismet` is a separate install.

## Related

- [Offensive — Overview](index.md) — this is part of Stage 1 (Reconnaissance)
- [Network & Infrastructure Enumeration](network-infrastructure-enumeration.md) — where an associated, in-scope network goes next
- Reference: [Wi-Fi Security (WEP, WPA, WPA2, WPA3)](../fundamentals/concepts/wifi-security.md) · [Wi-Fi Deauthentication and Rogue Access Points](../fundamentals/concepts/wifi-deauth-rogue-ap.md) · [WPA/WPA2 Passphrase Attacks (Handshake Capture)](../fundamentals/concepts/wifi-passphrase-attacks.md)
- Reference: [Packet Sniffing](../fundamentals/concepts/packet-sniffing.md) · [Man-in-the-Middle](../fundamentals/concepts/man-in-the-middle.md) · [Password Attacks](../fundamentals/concepts/password-attacks.md) · [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md)
- Defensive counterpart: [Wi-Fi Security (WEP, WPA, WPA2, WPA3)](../fundamentals/concepts/wifi-security.md) — WPA3/SAE, PMF/802.11w, 802.1X-EAP and disabling WPS are the fixes for every posture finding above

## External Resources & White Papers

- [Aircrack-ng documentation](https://www.aircrack-ng.org/documentation.html) — the survey/monitor-mode suite this page uses
- [Kismet Wireless](https://www.kismetwireless.net/) — passive discovery and WIDS
- [Wi-Fi Alliance — WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security) — SAE and PMF, the controls the findings map to
- [IEEE 802.11w — Management Frame Protection](https://standards.ieee.org/ieee/802.11w/3903/) — the standard behind PMF
- [NIST SP 800-153 — Guidelines for Securing Wireless Local Area Networks (WLANs)](https://csrc.nist.gov/pubs/sp/800/153/final) — the defensive baseline
