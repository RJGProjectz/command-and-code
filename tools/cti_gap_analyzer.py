#!/usr/bin/env python3
"""
tools/cti_gap_analyzer.py — Cyber Threat Intelligence & Detection Gap Analyzer

Zero-dependency standard-library Python engine that cross-references threat
actor TTP profiles against deployed detection queries and playbooks across
the Command & Code repository.

Usage:
  python tools/cti_gap_analyzer.py --all
  python tools/cti_gap_analyzer.py --actor "Volt Typhoon"
  python tools/cti_gap_analyzer.py --report
"""

import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

# Catalog of curated threat actor TTP mappings
THREAT_ACTORS = {
    "Midnight Blizzard": {
        "aliases": ["APT29", "Cozy Bear", "Nobelium"],
        "techniques": {
            "T1098.003": "Additional Cloud Credentials / OAuth Grants",
            "T1078.004": "Valid Accounts: Cloud Accounts",
            "T1059.001": "Command and Scripting: PowerShell",
            "T1562.008": "Impair Defenses: Disable Cloud Audit",
            "T1090": "Proxy: Residential Proxies",
            "T1106": "Native API: Graph API Interrogation"
        }
    },
    "Volt Typhoon": {
        "aliases": ["Vanguard Panda", "Bronze Silhouette"],
        "techniques": {
            "T1047": "Windows Management Instrumentation",
            "T1059.003": "Command and Scripting: Windows Command Shell",
            "T1016": "System Network Configuration Discovery",
            "T1090.001": "Port Proxying (netsh)",
            "T1003.003": "OS Credential Dumping: NTDS.dit",
            "T1490": "Inhibit System Recovery"
        }
    },
    "Scattered Spider": {
        "aliases": ["UNC3944", "Octo Tempest", "Muddled Libra"],
        "techniques": {
            "T1556": "Modify Authentication Process (MFA Reset)",
            "T1098.005": "Device Registration Manipulation",
            "T1562.001": "Impair Defenses: BYOVD Driver Unhooking",
            "T1021.001": "Remote Desktop Protocol",
            "T1219": "Remote Access Software"
        }
    },
    "BlackCat": {
        "aliases": ["ALPHV"],
        "techniques": {
            "T1486": "Data Encrypted for Impact",
            "T1490": "Inhibit System Recovery",
            "T1087.002": "Account Discovery: Domain Account",
            "T1567.002": "Exfiltration to Cloud Storage (Rclone/Mega)",
            "T1529": "System Shutdown/Reboot"
        }
    }
}

def scan_repository_techniques() -> dict:
    """Scans all markdown files in docs/ to locate referenced ATT&CK technique IDs."""
    technique_refs = {}
    for md_file in DOCS_DIR.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        # Match T1xxx or T1xxx.xxx
        matches = re.findall(r"\b(T1[0-9]{3}(?:\.[0-9]{3})?)\b", content)
        for tech in set(matches):
            if tech not in technique_refs:
                technique_refs[tech] = []
            technique_refs[tech].append(str(md_file.relative_to(REPO_ROOT)))
    return technique_refs

def analyze_actor(actor_name: str, actor_data: dict, repo_techs: dict) -> dict:
    covered = []
    missing = []
    
    for tech_id, desc in actor_data["techniques"].items():
        # Check exact or parent technique match (e.g., T1098 matching T1098.003)
        parent_id = tech_id.split(".")[0]
        refs = repo_techs.get(tech_id, []) or repo_techs.get(parent_id, [])
        if refs:
            covered.append({"id": tech_id, "desc": desc, "refs": len(refs), "sample": refs[0]})
        else:
            missing.append({"id": tech_id, "desc": desc})
            
    total = len(actor_data["techniques"])
    pct = (len(covered) / total * 100) if total else 0
    return {
        "actor": actor_name,
        "aliases": actor_data.get("aliases", []),
        "covered": covered,
        "missing": missing,
        "coverage_pct": pct
    }

def print_actor_report(result: dict):
    print(f"\n{'='*75}")
    print(f" THREAT ACTOR CTI GAP ANALYSIS: {result['actor'].upper()}")
    print(f" Aliases: {', '.join(result['aliases'])}")
    print(f" Coverage: {len(result['covered'])}/{len(result['covered']) + len(result['missing'])} ({result['coverage_pct']:.1f}%)")
    print(f"{'='*75}")
    
    print("\n[+] DETECTED / MONITORED TECHNIQUES:")
    for item in result["covered"]:
        print(f"  [COVERED] {item['id']:<10} {item['desc']:<38} ({item['refs']} docs, e.g. {item['sample']})")
        
    if result["missing"]:
        print("\n[-] DETECTION GAPS (UNMONITORED TTPs):")
        for item in result["missing"]:
            print(f"  [GAP]     {item['id']:<10} {item['desc']:<38} (No detection rule found)")
    else:
        print("\n[+] No detection gaps! 100% actor tradecraft covered.")
    print()

def generate_full_report(repo_techs: dict):
    print("\n| Threat Actor | Key Aliases | Techniques Evaluated | Covered | Gaps | Coverage |")
    print("| :--- | :--- | :---: | :---: | :---: | :---: |")
    total_cov = 0
    total_techs = 0
    for name, data in THREAT_ACTORS.items():
        res = analyze_actor(name, data, repo_techs)
        total_cov += len(res["covered"])
        total_techs += (len(res["covered"]) + len(res["missing"]))
        aliases_str = ", ".join(res["aliases"])
        print(f"| **{name}** | {aliases_str} | {len(res['covered']) + len(res['missing'])} | {len(res['covered'])} | {len(res['missing'])} | **{res['coverage_pct']:.1f}%** |")
    
    agg_pct = (total_cov / total_techs * 100) if total_techs else 0
    print(f"| **AGGREGATE TOTAL** | *All Actor Profiles* | **{total_techs}** | **{total_cov}** | **{total_techs - total_cov}** | **{agg_pct:.1f}%** |\n")

def main():
    repo_techs = scan_repository_techniques()
    
    if len(sys.argv) < 2 or sys.argv[1] == "--all":
        for name, data in THREAT_ACTORS.items():
            res = analyze_actor(name, data, repo_techs)
            print_actor_report(res)
    elif sys.argv[1] == "--actor":
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        matched = False
        for name, data in THREAT_ACTORS.items():
            if target.lower() in name.lower() or any(target.lower() in a.lower() for a in data.get("aliases", [])):
                res = analyze_actor(name, data, repo_techs)
                print_actor_report(res)
                matched = True
        if not matched:
            print(f"Threat actor '{target}' not found in catalog.")
    elif sys.argv[1] == "--report":
        generate_full_report(repo_techs)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
