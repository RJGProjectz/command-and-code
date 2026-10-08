#!/usr/bin/env python3
"""
tools/hunt_runner.py — Threat Hunting Framework & Playbook Management Engine

Zero-dependency standard-library Python utility for managing, validating,
and reporting on hypothesis-driven threat hunting playbooks across Command & Code.

Usage:
  python tools/hunt_runner.py --list
  python tools/hunt_runner.py --validate
  python tools/hunt_runner.py --template "Hunt Title"
  python tools/hunt_runner.py --report
"""

import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HUNT_DIR = REPO_ROOT / "docs" / "tasks" / "threat-hunting"

def parse_frontmatter(content: str) -> dict:
    """Extract YAML frontmatter fields from markdown content."""
    meta = {}
    if not content.startswith("---"):
        return meta
    parts = content.split("---", 2)
    if len(parts) < 3:
        return meta
    fm_text = parts[1]
    
    current_key = None
    for line in fm_text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if re.match(r"^[a-zA-Z0-9_-]+:", line):
            k, v = line.split(":", 1)
            current_key = k.strip()
            v = v.strip()
            if v:
                meta[current_key] = v
            else:
                meta[current_key] = []
        elif line.startswith("  - ") and current_key:
            val = line[4:].strip()
            if isinstance(meta.get(current_key), list):
                meta[current_key].append(val)
    return meta

def extract_code_blocks(content: str) -> list:
    """Extract fenced code block languages."""
    return re.findall(r"```([a-zA-Z0-9_-]+)", content)

def list_hunts():
    """List all threat hunting playbooks in docs/tasks/threat-hunting/."""
    hunts = sorted(HUNT_DIR.glob("*.md"))
    print(f"\n{'='*75}")
    print(f" COMMAND & CODE — THREAT HUNTING PLAYBOOK DIRECTORY")
    print(f"{'='*75}\n")
    
    count = 0
    for hunt_file in hunts:
        if hunt_file.name == "index.md":
            continue
        count += 1
        content = hunt_file.read_text(encoding="utf-8")
        meta = parse_frontmatter(content)
        title = meta.get("title", hunt_file.stem)
        platforms = ", ".join(meta.get("platforms", [])) if isinstance(meta.get("platforms"), list) else meta.get("platforms", "N/A")
        languages = ", ".join(meta.get("languages", [])) if isinstance(meta.get("languages"), list) else meta.get("languages", "N/A")
        blocks = extract_code_blocks(content)
        
        print(f"[{count:02d}] {title}")
        print(f"     Path     : {hunt_file.relative_to(REPO_ROOT)}")
        print(f"     Platforms: {platforms}")
        print(f"     Languages: {languages}")
        print(f"     Queries  : {len(blocks)} code blocks ({', '.join(set(blocks))})")
        print()
    print(f"Total Threat Hunting Playbooks: {count}\n")

def validate_hunts() -> bool:
    """Validate that all hunting playbooks adhere to quality and frontmatter standards."""
    hunts = sorted(HUNT_DIR.glob("*.md"))
    all_valid = True
    print(f"\n[+] Validating {len(hunts)} threat hunting playbooks...")
    
    for hunt_file in hunts:
        if hunt_file.name == "index.md":
            continue
        content = hunt_file.read_text(encoding="utf-8")
        meta = parse_frontmatter(content)
        errors = []
        
        if "title" not in meta:
            errors.append("Missing frontmatter 'title'")
        if "platforms" not in meta:
            errors.append("Missing frontmatter 'platforms'")
        if "languages" not in meta:
            errors.append("Missing frontmatter 'languages'")
        if "tasks" not in meta or "Threat Hunting" not in meta.get("tasks", []):
            errors.append("Missing 'Threat Hunting' in frontmatter 'tasks'")
            
        blocks = extract_code_blocks(content)
        if not blocks:
            errors.append("No executable queries or code blocks found")
            
        if errors:
            all_valid = False
            print(f"  [FAIL] {hunt_file.name}:")
            for err in errors:
                print(f"         - {err}")
        else:
            print(f"  [PASS] {hunt_file.name} ({len(blocks)} queries)")
            
    if all_valid:
        print("\n[OK] All threat hunting playbooks passed validation.\n")
    else:
        print("\n[ERROR] Playbook validation failed.\n")
    return all_valid

def generate_template(title: str):
    """Output a standard PEAK/TaHiTI threat hunting playbook template."""
    template = f"""---
title: Threat Hunting — {title}
type: workflow
platforms:
  - Windows
  - Microsoft Defender
  - Splunk
languages:
  - KQL
  - SPL
tasks:
  - Threat Hunting
  - Detection Engineering
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - threat-hunting
  - hypothesis-driven
---

# Threat Hunting — {title}

[Brief executive summary outlining the adversary technique, threat actor relevance, and operational hunting scope.]

---

## 1. Threat Hypothesis & Scope

* **Hypothesis ($H_1$):** Adversaries are leveraging [Technique Name] to evade detection controls and achieve [Objective].
* **Null Hypothesis ($H_0$):** Activity reflects documented administrative deployment or benign business processes.
* **MITRE ATT&CK Mapping:** T1xxx.xxx ([Technique Name])
* **Prerequisite Telemetry:** Process creation events with full command-line arguments (Sysmon Event ID 1 / MDE `DeviceProcessEvents`).

---

## 2. Threat Hunting Queries

### Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(14d)
| where FileName =~ "<TARGET_BINARY>"
| summarize HostCount = dcount(DeviceName), Executions = count() by ProcessCommandLine
| where HostCount <= 2
| sort by HostCount asc
```

### Splunk (SPL)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    Image="*\\\\<TARGET_BINARY>"
| stats count as ExecCount, dc(Computer) as HostCount by CommandLine
| where HostCount <= 2
| sort + HostCount
```

---

## 3. Finding Triage & Escalation Criteria

1. **True Positive Intrusion:** Immediate host isolation and SecOps escalation.
2. **Policy Hygiene:** Notify system owners to update administrative procedures.
3. **Detection Transition:** Formalize query into a persistent Sigma rule for automated alerting.
"""
    print(template)

def generate_report():
    """Generate Markdown retrospective table for hunting coverage."""
    hunts = sorted(HUNT_DIR.glob("*.md"))
    print("\n| Playbook | Platforms | Languages | Queries | Status |")
    print("| :--- | :--- | :--- | :---: | :---: |")
    for hunt_file in hunts:
        if hunt_file.name == "index.md":
            continue
        content = hunt_file.read_text(encoding="utf-8")
        meta = parse_frontmatter(content)
        title = meta.get("title", hunt_file.stem)
        platforms = ", ".join(meta.get("platforms", [])) if isinstance(meta.get("platforms"), list) else "N/A"
        languages = ", ".join(meta.get("languages", [])) if isinstance(meta.get("languages"), list) else "N/A"
        blocks = extract_code_blocks(content)
        print(f"| [{title}]({hunt_file.name}) | {platforms} | {languages} | {len(blocks)} | Verified |")
    print()

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
        
    arg = sys.argv[1]
    if arg == "--list":
        list_hunts()
    elif arg == "--validate":
        success = validate_hunts()
        sys.exit(0 if success else 1)
    elif arg == "--template":
        title = sys.argv[2] if len(sys.argv) > 2 else "New Threat Hunt"
        generate_template(title)
    elif arg == "--report":
        generate_report()
    else:
        print(f"Unknown option: {arg}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()
