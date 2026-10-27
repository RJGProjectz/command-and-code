#!/usr/bin/env python3
"""Build curated CIS-aligned Windows Server baseline catalogs (Member Server + Domain Controller).

Unlike tools/build_cis_catalog.py (which parses licensed Tenable .audit files), this generator
encodes a hand-authored, doc-checked Level 1 core taken from the FREE public sources:

  * CIS Microsoft Windows Server 2022 Benchmark (the PDF, registered-download) - recommendation
    IDs, titles and the settings/expected values only; no CIS rationale or remediation prose.
  * Microsoft Security Baseline for Windows Server 2022 (the GPO backups / policy spreadsheet
    Microsoft publishes free in the Security Compliance Toolkit).

It emits two catalogs in the shared cc.cis.catalog/1 schema so scripts/powershell/Invoke-CisWindowsAudit.ps1
and Invoke-PostureAudit.ps1 find them by host role:

  scripts/cis/catalogs/windows-server-2022-ms-v1.0.0.json   (profile MS)
  scripts/cis/catalogs/windows-server-2022-dc-v1.0.0.json   (profile DC)

This is a curated CORE (highest-value L1 account policy, security options, SMB/LM hardening,
UAC, firewall and advanced audit policy). It is designed to be extended; add entries to CORE_CHECKS
or PROFILE_CHECKS and bump the version. Every expected value is doc-checked; confirm against the
exact benchmark version your organisation is assessed against.

Usage:
  python tools/build_server_baseline_catalog.py
  python tools/build_server_baseline_catalog.py --version 1.0.0 --release 2022 --outdir scripts/cis/catalogs
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import pathlib


BENCHMARK = "CIS Microsoft Windows Server {release} Benchmark (curated L1 core)"
NOTICE = (
    "Curated Level 1 core. Recommendation IDs and titles are from the CIS Benchmark; the benchmark "
    "text is licensed by CIS and is not reproduced. Expected values are doc-checked against the free "
    "CIS Benchmark PDF and the Microsoft Security Baseline. This is a subset, not the full benchmark; "
    "confirm against the exact version your organisation is assessed against."
)

# Applicability: Windows Server build numbers (2019=17763, 2022=20348, 2025=26100). Keep broad.
APPLICABILITY = [
    {
        "source": "Registry",
        "key": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion",
        "name": "CurrentBuild",
        "expect": {"op": "range", "min": 17763, "max": None},
    }
]


def sec(id_, title, section, key, expect):
    return {"id": id_, "title": title, "level": "L1", "section": section,
            "tests": [{"source": "SecurityPolicy", "key": key, "expect": expect}]}


def reg(id_, title, section, key, name, expect, allow_missing=False):
    test = {"source": "Registry", "key": key, "name": name, "expect": expect}
    if allow_missing:
        test["allowMissing"] = True
    return {"id": id_, "title": title, "level": "L1", "section": section, "tests": [test]}


def aud(id_, title, subcategory, values):
    return {"id": id_, "title": title, "level": "L1", "section": "17",
            "tests": [{"source": "AuditPolicy", "subcategory": subcategory,
                       "expect": {"op": "in", "values": values}}]}


LSA = "HKLM\\System\\CurrentControlSet\\Control\\Lsa"
SYSTEM_POL = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
LMSERVER = "HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters"
LMWORK = "HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"
FW_DOMAIN = "HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
FW_PUBLIC = "HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"
NETLOGON = "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters"

# --- Shared Level 1 core (applies to Member Server and Domain Controller) --------------------
CORE_CHECKS = [
    # 1.1 Password policy
    sec("1.1.1", "Ensure 'Enforce password history' is set to '24 or more password(s)'",
        "1", "PasswordHistorySize", {"op": "range", "min": 24, "max": None}),
    sec("1.1.2", "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
        "1", "MaximumPasswordAge", {"op": "range", "min": 1, "max": 365}),
    sec("1.1.3", "Ensure 'Minimum password age' is set to '1 or more day(s)'",
        "1", "MinimumPasswordAge", {"op": "range", "min": 1, "max": None}),
    sec("1.1.4", "Ensure 'Minimum password length' is set to '14 or more character(s)'",
        "1", "MinimumPasswordLength", {"op": "range", "min": 14, "max": None}),
    sec("1.1.5", "Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
        "1", "PasswordComplexity", {"op": "eq", "value": "1"}),
    sec("1.1.7", "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'",
        "1", "ClearTextPassword", {"op": "eq", "value": "0"}),
    # 1.2 Lockout policy
    sec("1.2.1", "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
        "1", "LockoutDuration", {"op": "range", "min": 15, "max": None}),
    sec("1.2.2", "Ensure 'Account lockout threshold' is set to '5 or fewer, but not 0'",
        "1", "LockoutBadCount", {"op": "range", "min": 1, "max": 5}),
    sec("1.2.3", "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'",
        "1", "ResetLockoutCount", {"op": "range", "min": 15, "max": None}),
    # 2.3 Security options (registry-backed, language-independent)
    reg("2.3.1.1", "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is 'Enabled'",
        "2", LSA, "LimitBlankPasswordUse", {"op": "eq", "value": "1"}),
    reg("2.3.7.3", "Ensure 'Interactive logon: Machine inactivity limit' is '900 or fewer second(s), but not 0'",
        "2", SYSTEM_POL, "InactivityTimeoutSecs", {"op": "range", "min": 1, "max": 900}),
    reg("2.3.9.1", "Ensure 'Microsoft network server: Digitally sign communications (always)' is 'Enabled'",
        "2", LMSERVER, "RequireSecuritySignature", {"op": "eq", "value": "1"}),
    reg("2.3.8.1", "Ensure 'Microsoft network client: Digitally sign communications (always)' is 'Enabled'",
        "2", LMWORK, "RequireSecuritySignature", {"op": "eq", "value": "1"}),
    reg("2.3.11.5", "Ensure 'Network security: LAN Manager authentication level' is 'Send NTLMv2 response only. Refuse LM & NTLM'",
        "2", LSA, "LmCompatibilityLevel", {"op": "eq", "value": "5"}),
    reg("2.3.11.1", "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is 'Enabled'",
        "2", LSA, "NoLMHash", {"op": "eq", "value": "1"}),
    reg("2.3.10.2", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is 'Enabled'",
        "2", LSA, "RestrictAnonymousSAM", {"op": "eq", "value": "1"}),
    reg("2.3.10.3", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is 'Enabled'",
        "2", LSA, "RestrictAnonymous", {"op": "eq", "value": "1"}),
    # 2.3.17 UAC
    reg("2.3.17.1", "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is 'Enabled'",
        "2", SYSTEM_POL, "FilterAdministratorToken", {"op": "eq", "value": "1"}),
    reg("2.3.17.6", "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is 'Enabled'",
        "2", SYSTEM_POL, "EnableLUA", {"op": "eq", "value": "1"}),
    reg("2.3.17.3", "Ensure 'User Account Control: Behavior of the elevation prompt for administrators' is 'Prompt for consent on the secure desktop' or stricter",
        "2", SYSTEM_POL, "ConsentPromptBehaviorAdmin", {"op": "in", "values": ["1", "2"]}),
    # 9 Windows Firewall
    reg("9.1.1", "Ensure 'Windows Firewall: Domain: Firewall state' is 'On'",
        "9", FW_DOMAIN, "EnableFirewall", {"op": "eq", "value": "1"}),
    reg("9.3.1", "Ensure 'Windows Firewall: Public: Firewall state' is 'On'",
        "9", FW_PUBLIC, "EnableFirewall", {"op": "eq", "value": "1"}),
    # 18 Admin templates (high-value registry)
    reg("18.4.1", "Ensure 'Configure SMB v1 client driver' / legacy SMBv1 server is disabled",
        "18", LMSERVER, "SMB1", {"op": "eq", "value": "0"}, allow_missing=True),
    # 17 Advanced audit policy (subcategory names resolve to GUIDs in the engine)
    aud("17.1.1", "Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
        "Credential Validation", ["Success, Failure"]),
    aud("17.2.1", "Ensure 'Audit Security Group Management' is set to include 'Success'",
        "Security Group Management", ["Success", "Success, Failure"]),
    aud("17.2.5", "Ensure 'Audit User Account Management' is set to 'Success and Failure'",
        "User Account Management", ["Success, Failure"]),
    aud("17.2.2", "Ensure 'Audit Computer Account Management' is set to include 'Success'",
        "Computer Account Management", ["Success", "Success, Failure"]),
    aud("17.5.1", "Ensure 'Audit Account Lockout' is set to include 'Failure'",
        "Account Lockout", ["Failure", "Success, Failure"]),
    aud("17.5.3", "Ensure 'Audit Logon' is set to 'Success and Failure'",
        "Logon", ["Success, Failure"]),
    aud("17.5.4", "Ensure 'Audit Logoff' is set to include 'Success'",
        "Logoff", ["Success", "Success, Failure"]),
    aud("17.5.5", "Ensure 'Audit Special Logon' is set to include 'Success'",
        "Special Logon", ["Success", "Success, Failure"]),
    aud("17.7.1", "Ensure 'Audit Audit Policy Change' is set to include 'Success'",
        "Audit Policy Change", ["Success", "Success, Failure"]),
    aud("17.7.2", "Ensure 'Audit Authentication Policy Change' is set to include 'Success'",
        "Authentication Policy Change", ["Success", "Success, Failure"]),
    aud("17.8.1", "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'",
        "Sensitive Privilege Use", ["Success, Failure"]),
    aud("17.9.5", "Ensure 'Audit System Integrity' is set to 'Success and Failure'",
        "System Integrity", ["Success, Failure"]),
    aud("17.9.3", "Ensure 'Audit Security State Change' is set to include 'Success'",
        "Security State Change", ["Success", "Success, Failure"]),
    aud("17.6.1", "Ensure 'Audit Detailed Tracking: Process Creation' is set to include 'Success'",
        "Process Creation", ["Success", "Success, Failure"]),
    aud("17.3.1", "Ensure 'Audit Removable Storage' is set to 'Success and Failure'",
        "Removable Storage", ["Success, Failure"]),
]

# --- Domain Controller-only additions --------------------------------------------------------
DC_CHECKS = [
    reg("2.3.1.5", "Ensure 'Domain controller: Refuse machine account password changes' is 'Disabled'",
        "2", NETLOGON, "RefusePasswordChange", {"op": "eq", "value": "0"}, allow_missing=True),
    reg("2.3.1.6", "Ensure 'Domain controller: LDAP server channel binding token requirements' is 'Always'",
        "2", NETLOGON, "LdapEnforceChannelBinding", {"op": "eq", "value": "2"}, allow_missing=True),
    reg("2.3.6.6", "Ensure 'Domain controller: LDAP server signing requirements' is 'Require signing'",
        "2", "HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters",
        "LDAPServerIntegrity", {"op": "eq", "value": "2"}, allow_missing=True),
    aud("17.4.1", "Ensure 'Audit Directory Service Changes' is set to include 'Success'",
        "Directory Service Changes", ["Success", "Success, Failure"]),
]


def build(profile, release, version, checks, source_sha256):
    # The source of truth for a curated catalog is this generator file (the CIS PDF and MS baseline
    # are the human-read references named in the notice); its sha256 lets CI detect regeneration.
    return {
        "schema": "cc.cis.catalog/1",
        "benchmark": BENCHMARK.format(release=release),
        "version": version,
        "profile": profile,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "tools/build_server_baseline_catalog.py",
        "notice": NOTICE,
        "sources": [
            {"file": "tools/build_server_baseline_catalog.py", "sha256": source_sha256,
             "level": "L1", "profile": profile}
        ],
        "applicability": APPLICABILITY,
        "checks": checks,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="2022")
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--outdir", default="scripts/cis/catalogs")
    args = ap.parse_args()

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    source_sha256 = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    ms = build("MS", args.release, args.version, list(CORE_CHECKS), source_sha256)
    dc = build("DC", args.release, args.version, list(CORE_CHECKS) + list(DC_CHECKS), source_sha256)

    for profile, data in (("ms", ms), ("dc", dc)):
        path = outdir / f"windows-server-{args.release}-{profile}-v{args.version}.json"
        path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {path} ({len(data['checks'])} checks)")


if __name__ == "__main__":
    main()
