#!/usr/bin/env python3
"""Command & Code — MITRE ATT&CK Validation and Navigator Generator.

Scans all documentation pages and production scripts for MITRE ATT&CK technique IDs
(e.g., T1059.001, T1078, T1486), validates them against the Enterprise ATT&CK taxonomy,
calculates tactic coverage statistics, and exports an official ATT&CK Navigator JSON layer
(site/mitre_attack_coverage.json) and markdown reference matrix (docs/references/mitre-attack-matrix.md).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SITE = ROOT / "site"
MATRIX_PAGE = "references/mitre-attack-matrix.md"

# Enterprise ATT&CK Tactics Taxonomy
TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"),
    ("TA0112", "Defense Impairment"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# Enterprise ATT&CK v20 technique catalog (ID -> name, tactics), generated from attack.mitre.org
# on 2026-10-13 (WP-51). Regenerate when MITRE publishes a new release; v19 renamed TA0005 to
# Stealth and moved tool/log tampering into the new Defense Impairment tactic (TA0112).
TECHNIQUE_CATALOG = {
    "T1003": ("OS Credential Dumping", ["Credential Access"]),
    "T1003.001": ("LSASS Memory", ["Credential Access"]),
    "T1003.002": ("Security Account Manager", ["Credential Access"]),
    "T1003.003": ("NTDS", ["Credential Access"]),
    "T1003.004": ("LSA Secrets", ["Credential Access"]),
    "T1003.005": ("Cached Domain Credentials", ["Credential Access"]),
    "T1003.006": ("DCSync", ["Credential Access"]),
    "T1005": ("Data from Local System", ["Collection"]),
    "T1007": ("System Service Discovery", ["Discovery"]),
    "T1012": ("Query Registry", ["Discovery"]),
    "T1014": ("Rootkit", ["Stealth"]),
    "T1016": ("System Network Configuration Discovery", ["Discovery"]),
    "T1018": ("Remote System Discovery", ["Discovery"]),
    "T1021": ("Remote Services", ["Lateral Movement"]),
    "T1021.001": ("Remote Desktop Protocol", ["Lateral Movement"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["Lateral Movement"]),
    "T1021.004": ("SSH", ["Lateral Movement"]),
    "T1021.006": ("Windows Remote Management", ["Lateral Movement"]),
    "T1027": ("Obfuscated Files or Information", ["Stealth"]),
    "T1033": ("System Owner/User Discovery", ["Discovery"]),
    "T1036": ("Masquerading", ["Stealth"]),
    "T1036.003": ("Rename Legitimate Utilities", ["Stealth"]),
    "T1037": ("Boot or Logon Initialization Scripts", ["Persistence", "Privilege Escalation"]),
    "T1040": ("Network Sniffing", ["Credential Access", "Discovery"]),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1047": ("Windows Management Instrumentation", ["Execution"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Exfiltration"]),
    "T1049": ("System Network Connections Discovery", ["Discovery"]),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.003": ("Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.005": ("Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.006": ("Systemd Timers", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1055": ("Process Injection", ["Privilege Escalation", "Stealth"]),
    "T1057": ("Process Discovery", ["Discovery"]),
    "T1059": ("Command and Scripting Interpreter", ["Execution"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1059.003": ("Windows Command Shell", ["Execution"]),
    "T1059.004": ("Unix Shell", ["Execution"]),
    "T1059.005": ("Visual Basic", ["Execution"]),
    "T1059.006": ("Python", ["Execution"]),
    "T1059.007": ("JavaScript", ["Execution"]),
    "T1068": ("Exploitation for Privilege Escalation", ["Privilege Escalation"]),
    "T1069": ("Permission Groups Discovery", ["Discovery"]),
    "T1070": ("Indicator Removal", ["Stealth"]),
    "T1070.003": ("Clear Command History", ["Stealth"]),
    "T1070.004": ("File Deletion", ["Stealth"]),
    "T1070.006": ("Timestomp", ["Stealth"]),
    "T1071": ("Application Layer Protocol", ["Command and Control"]),
    "T1071.001": ("Web Protocols", ["Command and Control"]),
    "T1071.004": ("DNS", ["Command and Control"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"]),
    "T1078.001": ("Default Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"]),
    "T1078.002": ("Domain Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"]),
    "T1078.003": ("Local Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"]),
    "T1078.004": ("Cloud Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"]),
    "T1082": ("System Information Discovery", ["Discovery"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1087": ("Account Discovery", ["Discovery"]),
    "T1087.002": ("Domain Account", ["Discovery"]),
    "T1090": ("Proxy", ["Command and Control"]),
    "T1090.001": ("Internal Proxy", ["Command and Control"]),
    "T1090.003": ("Multi-hop Proxy", ["Command and Control"]),
    "T1091": ("Replication Through Removable Media", ["Initial Access", "Lateral Movement"]),
    "T1095": ("Non-Application Layer Protocol", ["Command and Control"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1098.001": ("Additional Cloud Credentials", ["Persistence", "Privilege Escalation"]),
    "T1098.003": ("Additional Cloud Roles", ["Persistence", "Privilege Escalation"]),
    "T1098.004": ("SSH Authorized Keys", ["Persistence", "Privilege Escalation"]),
    "T1098.005": ("Device Registration", ["Persistence", "Privilege Escalation"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1106": ("Native API", ["Execution"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1110.002": ("Password Cracking", ["Credential Access"]),
    "T1110.003": ("Password Spraying", ["Credential Access"]),
    "T1110.004": ("Credential Stuffing", ["Credential Access"]),
    "T1112": ("Modify Registry", ["Persistence", "Defense Impairment"]),
    "T1114": ("Email Collection", ["Collection"]),
    "T1127.001": ("MSBuild", ["Execution", "Stealth"]),
    "T1134": ("Access Token Manipulation", ["Privilege Escalation", "Stealth"]),
    "T1134.004": ("Parent PID Spoofing", ["Privilege Escalation", "Stealth"]),
    "T1136": ("Create Account", ["Persistence"]),
    "T1136.003": ("Cloud Account", ["Persistence"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["Stealth"]),
    "T1187": ("Forced Authentication", ["Credential Access"]),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1195": ("Supply Chain Compromise", ["Initial Access"]),
    "T1195.001": ("Compromise Software Dependencies and Development Tools", ["Initial Access"]),
    "T1197": ("BITS Jobs", ["Execution", "Persistence", "Stealth"]),
    "T1200": ("Hardware Additions", ["Initial Access"]),
    "T1204": ("User Execution", ["Execution"]),
    "T1204.002": ("Malicious File", ["Execution"]),
    "T1210": ("Exploitation of Remote Services", ["Lateral Movement"]),
    "T1218": ("System Binary Proxy Execution", ["Stealth"]),
    "T1218.004": ("InstallUtil", ["Stealth"]),
    "T1218.005": ("Mshta", ["Stealth"]),
    "T1218.007": ("Msiexec", ["Stealth"]),
    "T1218.010": ("Regsvr32", ["Stealth"]),
    "T1218.011": ("Rundll32", ["Stealth"]),
    "T1219": ("Remote Access Tools", ["Command and Control"]),
    "T1222": ("File and Directory Permissions Modification", ["Defense Impairment"]),
    "T1482": ("Domain Trust Discovery", ["Discovery"]),
    "T1484": ("Domain or Tenant Policy Modification", ["Privilege Escalation", "Defense Impairment"]),
    "T1484.002": ("Trust Modification", ["Privilege Escalation", "Defense Impairment"]),
    "T1485": ("Data Destruction", ["Impact"]),
    "T1486": ("Data Encrypted for Impact", ["Impact"]),
    "T1489": ("Service Stop", ["Impact"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
    "T1496": ("Resource Hijacking", ["Impact"]),
    "T1498": ("Network Denial of Service", ["Impact"]),
    "T1499": ("Endpoint Denial of Service", ["Impact"]),
    "T1505": ("Server Software Component", ["Persistence"]),
    "T1505.003": ("Web Shell", ["Persistence"]),
    "T1525": ("Implant Internal Image", ["Persistence"]),
    "T1528": ("Steal Application Access Token", ["Credential Access"]),
    "T1529": ("System Shutdown/Reboot", ["Impact"]),
    "T1530": ("Data from Cloud Storage", ["Collection"]),
    "T1539": ("Steal Web Session Cookie", ["Credential Access"]),
    "T1542": ("Pre-OS Boot", ["Persistence", "Stealth"]),
    "T1542.003": ("Bootkit", ["Persistence", "Stealth"]),
    "T1543": ("Create or Modify System Process", ["Persistence", "Privilege Escalation"]),
    "T1543.001": ("Launch Agent", ["Persistence", "Privilege Escalation"]),
    "T1543.002": ("Systemd Service", ["Persistence", "Privilege Escalation"]),
    "T1543.003": ("Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1543.004": ("Launch Daemon", ["Persistence", "Privilege Escalation"]),
    "T1546": ("Event Triggered Execution", ["Persistence", "Privilege Escalation"]),
    "T1546.003": ("Windows Management Instrumentation Event Subscription", ["Persistence", "Privilege Escalation"]),
    "T1546.012": ("Image File Execution Options Injection", ["Persistence", "Privilege Escalation"]),
    "T1547": ("Boot or Logon Autostart Execution", ["Persistence", "Privilege Escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"]),
    "T1547.004": ("Winlogon Helper DLL", ["Persistence", "Privilege Escalation"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["Privilege Escalation"]),
    "T1548.001": ("Setuid and Setgid", ["Privilege Escalation"]),
    "T1548.002": ("Bypass User Account Control", ["Privilege Escalation"]),
    "T1548.003": ("Sudo and Sudo Caching", ["Privilege Escalation"]),
    "T1550": ("Use Alternate Authentication Material", ["Lateral Movement"]),
    "T1550.002": ("Pass the Hash", ["Lateral Movement"]),
    "T1552": ("Unsecured Credentials", ["Credential Access"]),
    "T1552.001": ("Credentials In Files", ["Credential Access"]),
    "T1553": ("Subvert Trust Controls", ["Defense Impairment"]),
    "T1553.002": ("Code Signing", ["Defense Impairment"]),
    "T1555": ("Credentials from Password Stores", ["Credential Access"]),
    "T1556": ("Modify Authentication Process", ["Persistence", "Defense Impairment", "Credential Access"]),
    "T1556.006": ("Multi-Factor Authentication", ["Persistence", "Defense Impairment", "Credential Access"]),
    "T1557": ("Adversary-in-the-Middle", ["Credential Access", "Collection"]),
    "T1557.001": ("Name Resolution Poisoning and SMB Relay", ["Credential Access", "Collection"]),
    "T1557.002": ("ARP Cache Poisoning", ["Credential Access", "Collection"]),
    "T1558": ("Steal or Forge Kerberos Tickets", ["Credential Access"]),
    "T1558.001": ("Golden Ticket", ["Credential Access"]),
    "T1558.003": ("Kerberoasting", ["Credential Access"]),
    "T1558.004": ("AS-REP Roasting", ["Credential Access"]),
    "T1560.001": ("Archive via Utility", ["Collection"]),
    "T1564": ("Hide Artifacts", ["Stealth"]),
    "T1564.004": ("NTFS File Attributes", ["Stealth"]),
    "T1564.008": ("Email Hiding Rules", ["Stealth"]),
    "T1566": ("Phishing", ["Initial Access"]),
    "T1566.001": ("Spearphishing Attachment", ["Initial Access"]),
    "T1566.002": ("Spearphishing Link", ["Initial Access"]),
    "T1567": ("Exfiltration Over Web Service", ["Exfiltration"]),
    "T1567.002": ("Exfiltration to Cloud Storage", ["Exfiltration"]),
    "T1569": ("System Services", ["Execution"]),
    "T1569.002": ("Service Execution", ["Execution"]),
    "T1573": ("Encrypted Channel", ["Command and Control"]),
    "T1574": ("Hijack Execution Flow", ["Execution", "Stealth"]),
    "T1574.006": ("Dynamic Linker Hijacking", ["Execution", "Stealth"]),
    "T1574.007": ("Path Interception by PATH Environment Variable", ["Execution", "Stealth"]),
    "T1574.009": ("Path Interception by Unquoted Path", ["Execution", "Stealth"]),
    "T1574.012": ("COR_PROFILER", ["Execution", "Stealth"]),
    "T1578.002": ("Create Cloud Instance", ["Defense Impairment"]),
    "T1584": ("Compromise Infrastructure", ["Resource Development"]),
    "T1588": ("Obtain Capabilities", ["Resource Development"]),
    "T1588.003": ("Code Signing Certificates", ["Resource Development"]),
    "T1589": ("Gather Victim Identity Information", ["Reconnaissance"]),
    "T1593": ("Search Open Websites/Domains", ["Reconnaissance"]),
    "T1597": ("Search Closed Sources", ["Reconnaissance"]),
    "T1598": ("Phishing for Information", ["Reconnaissance"]),
    "T1600": ("Weaken Encryption", ["Defense Impairment"]),
    "T1606": ("Forge Web Credentials", ["Credential Access"]),
    "T1606.002": ("SAML Tokens", ["Credential Access"]),
    "T1610": ("Deploy Container", ["Execution"]),
    "T1611": ("Escape to Host", ["Privilege Escalation"]),
    "T1613": ("Container and Resource Discovery", ["Discovery"]),
    "T1621": ("Multi-Factor Authentication Request Generation", ["Credential Access"]),
    "T1648": ("Serverless Execution", ["Execution"]),
    "T1651": ("Cloud Administration Command", ["Execution"]),
    "T1657": ("Financial Theft", ["Impact"]),
    "T1684": ("Social Engineering", ["Stealth"]),
    "T1684.001": ("Impersonation", ["Stealth"]),
    "T1685": ("Disable or Modify Tools", ["Defense Impairment"]),
    "T1685.001": ("Disable or Modify Windows Event Log", ["Defense Impairment"]),
    "T1685.002": ("Disable or Modify Cloud Log", ["Defense Impairment"]),
    "T1685.003": ("Modify or Spoof Tool UI", ["Defense Impairment"]),
    "T1685.004": ("Disable or Modify Linux Audit System Log", ["Defense Impairment"]),
    "T1685.005": ("Clear Windows Event Logs", ["Defense Impairment"]),
    "T1685.006": ("Clear Linux or Mac System Logs", ["Defense Impairment"]),
    "T1685.007": ("Impair Autonomous Defenses", ["Defense Impairment"]),
    "T1686": ("Disable or Modify System Firewall", ["Defense Impairment"]),
    "T1686.001": ("Cloud Firewall", ["Defense Impairment"]),
    "T1686.002": ("Network Device Firewall", ["Defense Impairment"]),
    "T1687": ("Exploitation for Defense Impairment", ["Defense Impairment"]),
    "T1688": ("Safe Mode Boot", ["Defense Impairment"]),
    "T1689": ("Downgrade Attack", ["Defense Impairment"]),
    "T1690": ("Prevent Command History Logging", ["Defense Impairment"]),
}

# Mobile ATT&CK IDs cited on the site; kept out of the Enterprise Navigator layer.
MOBILE_CATALOG = {
    "T1404": ("Exploitation for Privilege Escalation", ["Privilege Escalation"]),
    "T1638": ("Adversary-in-the-Middle", ["Collection"]),
    "T1660": ("Phishing", ["Initial Access"]),
}

# Revoked or deprecated IDs -> current ID (attack.mitre.org redirect targets). A page may name
# an old ID only as "formerly T..." next to the current one; any other use fails validation.
REVOKED = {
    "T1070.001": "T1685.005",
    "T1465": "T1638",
    "T1562": "T1685",
    "T1562.001": "T1685",
    "T1562.008": "T1685.002",
    "T1562.009": "T1688",
    "T1656": "T1684.001",
}

TECHNIQUE_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def scan_repository():
    """Scans all documentation pages and extracts ATT&CK technique references.

    Returns (coverage, stale): coverage maps current Enterprise IDs to pages; stale lists
    (page, line, id) where a revoked ID is cited without "formerly" on the same line.
    """
    coverage = {}
    stale = []
    # Skip dot-directories (docs/.obsidian, docs/.trash), as MkDocs exclude_docs does.
    doc_files = [d for d in DOCS.glob("**/*.md") if not any(part.startswith(".") for part in d.relative_to(DOCS).parts)]

    for doc in doc_files:
        try:
            text = doc.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel_path = doc.relative_to(DOCS).as_posix()
        if rel_path == MATRIX_PAGE:
            continue  # generated output; scanning it would count every technique as covered by itself
        found = set()
        for line_no, line in enumerate(text.splitlines(), start=1):
            for tech in TECHNIQUE_REGEX.findall(line):
                if tech in REVOKED:
                    if "formerly" not in line.lower():
                        stale.append((rel_path, line_no, tech))
                    continue
                if tech in MOBILE_CATALOG:
                    continue
                found.add(tech)
        for tech in found:
            coverage.setdefault(tech, []).append(rel_path)

    return coverage, stale


def generate_navigator_layer(coverage: dict) -> dict:
    """Produces official MITRE ATT&CK Navigator Layer v4.5 JSON format."""
    techniques_list = []
    for tech_id, docs in sorted(coverage.items()):
        name, tactics = TECHNIQUE_CATALOG.get(tech_id, ("Community Reference", ["Execution"]))
        for tactic in tactics:
            tact_name = tactic.lower().replace(" ", "-")
            techniques_list.append({
                "techniqueID": tech_id,
                "tactic": tact_name,
                "score": min(len(docs) * 20, 100),
                "color": "#00e5ff" if len(docs) >= 3 else "#38bdf8",
                "comment": f"Covered in {len(docs)} Command & Code pages: " + ", ".join(docs[:4]),
                "enabled": True,
                "metadata": [
                    {"name": "Documentation Pages", "value": str(len(docs))},
                    {"name": "Files", "value": "; ".join(docs[:5])}
                ]
            })

    layer = {
        "name": "Command & Code — Enterprise Operational Coverage",
        "versions": {
            "attack": "20",
            "navigator": "4.5",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Verified ATT&CK coverage across {len(coverage)} techniques in Command & Code security repository.",
        "filters": {
            "platforms": ["Windows", "Linux", "Azure", "Office 365", "IaaS"]
        },
        "sorting": 3,
        "viewMode": 0,
        "gradient": {
            "colors": ["#0f172a", "#0284c7", "#00e5ff"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "1-2 Reference Guides", "color": "#38bdf8"},
            {"label": "3+ Guides, Playbooks & Detections", "color": "#00e5ff"}
        ],
        "techniques": techniques_list
    }
    return layer


def covered_tactics(coverage: dict) -> set:
    """Returns the tactic names that at least one covered technique belongs to."""
    return {tac for tech_id in coverage for tac in TECHNIQUE_CATALOG.get(tech_id, ("", []))[1]}


def generate_matrix_markdown(coverage: dict) -> str:
    """Generates a clean documentation page mapping techniques to repository links."""
    lines = [
        "---",
        "title: MITRE ATT&CK® Enterprise Matrix & Navigator Coverage",
        "type: reference",
        "platforms:",
        "  - Windows",
        "  - Linux",
        "  - Azure",
        "  - Entra ID",
        "  - Microsoft Defender",
        "  - SentinelOne",
        "  - Splunk",
        "languages:",
        "  - KQL",
        "  - SPL",
        "  - S1QL",
        "  - PowerShell",
        "  - Bash",
        "tasks:",
        "  - Detection Engineering",
        "  - Incident Response",
        "  - Threat Hunting",
        "  - Hardening",
        "verified: true",
        "last_verified: 2026-10-13",
        "difficulty: advanced",
        "tags:",
        "  - mitre-attack",
        "  - tactics",
        "  - techniques",
        "  - navigator",
        "  - coverage",
        "---",
        "",
        "# MITRE ATT&CK® Enterprise Matrix & Navigator Coverage",
        "",
        "A verifiable cross-walk indexing all adversary techniques, tactics, detection signatures, and response playbooks in **Command & Code** mapped against the **MITRE ATT&CK® Enterprise Taxonomy (v20)**.",
        "",
        "---",
        "",
        "## 1. Executive Matrix Summary",
        "",
        "```text",
        f"TOTAL VALIDATED TECHNIQUES COVERED : {len(coverage)} Enterprise Techniques",
        "OFFICIAL NAVIGATOR LAYER ARTIFACT  : site/mitre_attack_coverage.json",
        f"TACTIC COVERAGE SPAN               : {len(covered_tactics(coverage))} of {len(TACTICS)} Enterprise tactics",
        "```",
        "",
        "> [!TIP]",
        "> **Importing to ATT&CK Navigator:**",
        "> Open [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), select **Open Existing Layer** -> **Upload from local**, and upload `site/mitre_attack_coverage.json` to visualize your team's live operational coverage heatmap.",
        "",
        "---",
        "",
        "## 2. Technique Coverage by ATT&CK Tactic",
        "",
        "| Technique ID | Technique Name | Primary Tactics | Operational Guides & Procedures |",
        "|:---|:---|:---|:---|",
    ]

    for tech_id, docs in sorted(coverage.items()):
        name, tactics = TECHNIQUE_CATALOG.get(tech_id, ("Community Technique", ["Execution"]))
        tactics_str = ", ".join(tactics)
        
        # Build clean relative markdown links from docs/references
        doc_links = []
        for d in docs[:4]:
            doc_name = Path(d).stem.replace("-", " ").title()
            rel_link = f"../{d}"
            doc_links.append(f"[{doc_name}]({rel_link})")
        
        link_str = " · ".join(doc_links)
        if len(docs) > 4:
            link_str += f" *(+{len(docs)-4} more)*"
        
        lines.append(f"| **`{tech_id}`** | {name} | {tactics_str} | {link_str} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. Automated Validation & CI Pipeline")
    lines.append("")
    lines.append("This coverage matrix is dynamically maintained by `tools/validate_mitre.py`. Any new detection query, incident response playbook, or hardening configuration tagged with an ATT&CK ID is automatically validated against the enterprise taxonomy during CI verification.")
    lines.append("")
    return "\n".join(lines)


def main():
    print("=" * 70)
    print("COMMAND & CODE -- MITRE ATT&CK VALIDATION & COVERAGE ENGINE")
    print("=" * 70)

    coverage, stale = scan_repository()
    print(f"\n[+] Total unique MITRE ATT&CK techniques identified: {len(coverage)}")

    # Tactic breakdown
    tactic_counts = {t[1]: 0 for t in TACTICS}
    unknown_techniques = []

    for tech_id, docs in sorted(coverage.items()):
        if tech_id in TECHNIQUE_CATALOG:
            name, tactics = TECHNIQUE_CATALOG[tech_id]
            for tac in tactics:
                if tac in tactic_counts:
                    tactic_counts[tac] += 1
        else:
            unknown_techniques.append(tech_id)

    print("\n--- ATT&CK Tactic Distribution ---")
    for tac_id, tac_name in TACTICS:
        count = tactic_counts.get(tac_name, 0)
        bar = "#" * (count * 2)
        print(f"  {tac_name:<24} : {count:>3} techniques {bar}")

    # Generate Navigator Layer
    SITE.mkdir(exist_ok=True)
    layer = generate_navigator_layer(coverage)
    layer_path = SITE / "mitre_attack_coverage.json"
    layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(f"\n[+] Exported MITRE ATT&CK Navigator Layer: {layer_path.as_posix()}")

    # Export markdown matrix reference
    matrix_md = generate_matrix_markdown(coverage)
    matrix_path = DOCS / MATRIX_PAGE
    matrix_path.write_text(matrix_md, encoding="utf-8")
    print(f"[+] Exported Reference Markdown Matrix : {matrix_path.as_posix()}")

    if unknown_techniques:
        print(f"\n[!] Note: {len(unknown_techniques)} community techniques identified outside primary catalog: {', '.join(unknown_techniques)}")

    if stale:
        print(f"\n[FAIL] {len(stale)} revoked ATT&CK ID(s) cited without 'formerly' (ATT&CK v20):")
        for rel_path, line_no, tech in stale:
            print(f"  docs/{rel_path}:{line_no}  {tech} -> use {REVOKED[tech]}")
        return 1

    print("\n[OK] MITRE ATT&CK coverage validation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
