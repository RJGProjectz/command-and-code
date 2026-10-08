#!/usr/bin/env python3
"""Audit LOLBAS (Living Off The Land Binaries and Scripts) and GTFOBins telemetry

and detection coverage across Command & Code repository.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Curated catalog of primary high-risk LOLBAS (Windows) and GTFOBins (Linux) binaries
LOLBAS_TARGETS = [
    ("certutil.exe", "T1105 / T1140", "Ingress Tool Transfer / Deobfuscation"),
    ("mshta.exe", "T1218.005", "Signed Binary Proxy Execution"),
    ("bitsadmin.exe", "T1197", "BITS Jobs Persistence / Download"),
    ("rundll32.exe", "T1218.011", "Signed Binary Proxy Execution"),
    ("regsvr32.exe", "T1218.010", "Squiblydoo Proxy Execution"),
    ("msbuild.exe", "T1127.001", "Trusted Developer Utilities"),
    ("wmic.exe", "T1047", "WMI Command-Line Execution"),
    ("cscript.exe", "T1059.005", "VBScript / JScript Execution"),
    ("wscript.exe", "T1059.005", "Visual Basic / Script Engine"),
    ("installutil.exe", "T1218.004", "InstallUtil Proxy Execution"),
    ("powershell.exe", "T1059.001", "Command and Scripting Interpreter"),
    ("cmd.exe", "T1059.003", "Windows Command Shell"),
    ("reg.exe", "T1112", "Modify Registry"),
    ("schtasks.exe", "T1053.005", "Scheduled Task Persistence"),
    ("net.exe", "T1087 / T1069", "Account & Group Discovery"),
    ("nltest.exe", "T1482", "Domain Trust Discovery"),
    ("whoami.exe", "T1033", "System Owner/User Discovery"),
    ("vssadmin.exe", "T1490", "Inhibit System Recovery (Shadow Deletion)"),
    ("sc.exe", "T1543.003", "Windows Service Creation"),
    ("msiexec.exe", "T1218.007", "Windows Installer Proxy Execution"),
]

GTFOBINS_TARGETS = [
    ("bash", "T1059.004", "Unix Shell Execution / Reverse Shell"),
    ("python", "T1059.006", "Python Scripting / Reverse Shell"),
    ("find", "T1548.001", "Setuid / Sudo Binary Abuse"),
    ("vim", "T1548.001", "Shell Escape via Sudo / SUID"),
    ("awk", "T1059.004", "File Read / Shell Spawning"),
    ("nc", "T1095 / T1105", "Non-Application Protocol / Egress"),
    ("socat", "T1095", "Relay / Reverse Shell"),
    ("curl", "T1105", "Ingress Tool Transfer"),
    ("wget", "T1105", "Ingress Tool Transfer"),
    ("sudo", "T1548.003", "Sudo and Sudo Caching"),
    ("systemctl", "T1543.002", "Systemd Service Persistence"),
    ("crontab", "T1053.003", "Cron Persistence"),
    ("tar", "T1560.001", "Archive Collected Data"),
    ("pkexec", "T1548.001", "Local Privilege Escalation (PwnKit)"),
]


def audit_coverage() -> tuple[list[dict], list[dict]]:
    detection_dirs = [
        ROOT / "docs" / "detection",
        ROOT / "docs" / "tasks" / "threat-hunting",
        ROOT / "docs" / "tasks" / "investigation",
        ROOT / "docs" / "tasks" / "incident-response",
        ROOT / "docs" / "languages",
        ROOT / "docs" / "platforms",
    ]

    all_files: list[pathlib.Path] = []
    for d in detection_dirs:
        if d.exists():
            all_files.extend(d.rglob("*.md"))

    file_contents = {f: f.read_text(encoding="utf-8").lower() for f in all_files}

    lolbas_results = []
    for binary, technique, desc in LOLBAS_TARGETS:
        pattern = re.compile(re.escape(binary.lower()))
        matching_files = [
            f.relative_to(ROOT).as_posix()
            for f, content in file_contents.items()
            if pattern.search(content)
        ]
        lolbas_results.append({
            "target": binary,
            "technique": technique,
            "description": desc,
            "hits": len(matching_files),
            "covered": len(matching_files) > 0,
            "files": matching_files[:3],
        })

    gtfobins_results = []
    for binary, technique, desc in GTFOBINS_TARGETS:
        pattern = re.compile(r"\b" + re.escape(binary.lower()) + r"\b")
        matching_files = [
            f.relative_to(ROOT).as_posix()
            for f, content in file_contents.items()
            if pattern.search(content)
        ]
        gtfobins_results.append({
            "target": binary,
            "technique": technique,
            "description": desc,
            "hits": len(matching_files),
            "covered": len(matching_files) > 0,
            "files": matching_files[:3],
        })

    return lolbas_results, gtfobins_results


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit LOLBAS & GTFOBins coverage")
    parser.add_argument("--markdown", action="store_true", help="Output markdown table")
    args = parser.parse_args()

    lolbas_res, gtfobins_res = audit_coverage()

    lolbas_cov = sum(1 for r in lolbas_res if r["covered"])
    gtfo_cov = sum(1 for r in gtfobins_res if r["covered"])
    total_cov = lolbas_cov + gtfo_cov
    total_targets = len(lolbas_res) + len(gtfobins_res)
    pct = (total_cov / total_targets) * 100

    if args.markdown:
        print("# Living-Off-The-Land Coverage Matrix\n")
        print(f"Overall Coverage: **{total_cov}/{total_targets} ({pct:.1f}%)**\n")
        print("## Windows LOLBAS Binaries\n")
        print("| Binary | Technique | Purpose | Covered | Top References |")
        print("| :--- | :--- | :--- | :---: | :--- |")
        for r in lolbas_res:
            status = "Yes" if r["covered"] else "No"
            refs = ", ".join(f"`{f}`" for f in r["files"]) or "-"
            print(f"| `{r['target']}` | {r['technique']} | {r['description']} | {status} | {refs} |")
        print("\n## Linux GTFOBins Binaries\n")
        print("| Binary | Technique | Purpose | Covered | Top References |")
        print("| :--- | :--- | :--- | :---: | :--- |")
        for r in gtfobins_res:
            status = "Yes" if r["covered"] else "No"
            refs = ", ".join(f"`{f}`" for f in r["files"]) or "-"
            print(f"| `{r['target']}` | {r['technique']} | {r['description']} | {status} | {refs} |")
        return 0

    print("===============================================================")
    print("      COMMAND & CODE - LOLBAS & GTFOBINS COVERAGE AUDIT        ")
    print("===============================================================")
    print(f"\n[+] Windows LOLBAS Coverage : {lolbas_cov}/{len(lolbas_res)} ({lolbas_cov/len(lolbas_res)*100:.1f}%)")
    for r in lolbas_res:
        status = "[COVERED]" if r["covered"] else "[MISSING]"
        print(f"  {status:9} {r['target']:16} {r['technique']:14} ({r['hits']} references)")

    print(f"\n[+] Linux GTFOBins Coverage : {gtfo_cov}/{len(gtfobins_res)} ({gtfo_cov/len(gtfobins_res)*100:.1f}%)")
    for r in gtfobins_res:
        status = "[COVERED]" if r["covered"] else "[MISSING]"
        print(f"  {status:9} {r['target']:16} {r['technique']:14} ({r['hits']} references)")

    print("\n---------------------------------------------------------------")
    print(f"TOTAL LIVING-OFF-THE-LAND COVERAGE: {total_cov}/{total_targets} ({pct:.1f}%)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
