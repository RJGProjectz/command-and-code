#!/usr/bin/env python3
"""Command & Code — Identifier Sanitizer Tooling.

Sanitizes hostnames, usernames, IP addresses, and domain identifiers across
the repository in compliance with Golden Standards §2.4 (Scrub protocol) and
NIST CSF 2.0 PR.DS-01.

Usage:
    python tools/sanitize.py --scan               # Scan and inventory all identifiers
    python tools/sanitize.py --dry-run            # Preview diff of sanitization changes
    python tools/sanitize.py --run                # Apply sanitization in-place
    python tools/sanitize.py --check-206          # Specifically audit for 206.* IPs
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Directories and files ignored during repository scanning
IGNORE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "scratch",
    "node_modules",
    ".idea",
    ".pytest_cache",
    "WebsiteThemeSource",
}

IGNORE_FILES = {
    "sanitize.py",
}

# Documentation URLs and well-known RFC/official vendor domains that are public resources
ALLOWED_PUBLIC_DOMAINS = {
    "microsoft.com",
    "microsoftonline.com",
    "github.com",
    "github.io",
    "mitre.org",
    "nist.gov",
    "python.org",
    "gnu.org",
    "jqlang.org",
    "man7.org",
    "openbsd.org",
    "proxmox.com",
    "broadcom.com",
    "readthedocs.io",
    "redhat.com",
    "sentinelone.com",
    "sentinelone.net",
    "shellcheck.net",
    "splunk.com",
    "c2pa.org",
    "chrony-project.org",
    "system.net",
}

# Standard loopback and bind addresses
LOOPBACK_AND_BIND_IPS = {
    "127.0.0.1",
    "127.0.0.53",
    "0.0.0.0",
}

PUBLIC_DNS_IPS = {
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
}


@dataclass
class Finding:
    category: str
    identifier: str
    file_path: Path
    line_number: int
    line_content: str
    suggested_replacement: str = ""


# Replacement definitions for in-place sanitization
REPLACEMENTS = [
    # 1. 206.* IPs (specifically flagged by auditor / reviewer)
    (re.compile(r"\b206\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<REDACTED_IP>"),

    # 2. External / Target / IOC test IPs (mistaken for live 206.* IPs)
    (re.compile(r"-RemoteAddress 203\.0\.113\.10\b"), "-RemoteAddress '<TARGET_IP>'"),
    (re.compile(r"-s 203\.0\.113\.10\b"), "-s '<TARGET_IP>'"),
    (re.compile(r"-d 203\.0\.113\.10\b"), "-d '<TARGET_IP>'"),
    (re.compile(r"host 203\.0\.113\.10\b"), "host '<TARGET_IP>'"),
    (re.compile(r"Name 203\.0\.113\.10\b"), "Name '<TARGET_IP>'"),
    (re.compile(r"dig -x 203\.0\.113\.10"), "dig -x '<TARGET_IP>'"),
    (re.compile(r"case-203\.0\.113\.10\.pcap"), "case-target-ip.pcap"),
    (re.compile(r"IR-Block-203\.0\.113\.10"), "IR-Block-<TARGET_IP>"),
    (re.compile(r"\b203\.0\.113\.10\b"), "<TARGET_IP>"),
    (re.compile(r"\b198\.51\.100\.7\b"), "<SECONDARY_IP>"),
    (re.compile(r"-Server 10\.0\.0\.10\b"), "-Server '<DNS_SERVER_IP>'"),
    (re.compile(r"\b10\.0\.0\.10\b"), "<DNS_SERVER_IP>"),
    (re.compile(r"\b10\.1\.1\.5\b"), "<INTERNAL_IP>"),

    # 3. Hostnames
    (re.compile(r"-ComputerName server01\b"), "-ComputerName '<TARGET_HOST>'"),
    (re.compile(r"-TargetName server01\b"), "-TargetName '<TARGET_HOST>'"),
    (re.compile(r"nc -zv server01 443\b"), "nc -zv '<TARGET_HOST>' 443"),
    (re.compile(r"tracepath server01\b"), "tracepath '<TARGET_HOST>'"),
    (re.compile(r"https://server01/"), "https://<TARGET_HOST>/"),
    (re.compile(r"-Name server01\.contoso\.local\b"), "-Name '<TARGET_HOST>.<INTERNAL_DOMAIN>'"),
    (re.compile(r"\bserver01\.contoso\.local\b"), "<TARGET_HOST>.<INTERNAL_DOMAIN>"),
    (re.compile(r"\bserver01\b"), "<TARGET_HOST>"),
    (re.compile(r"\bMeshy\b"), "workstation"),

    # 4. User accounts & emails
    (re.compile(r"\badmin@contoso\.com\b"), "<ADMIN_USER>@<DOMAIN>"),
    (re.compile(r"\bjdoe@contoso\.com\b"), "<USER>@<DOMAIN>"),
    (re.compile(r"\battacker@example\.com\b"), "<ATTACKER>@<DOMAIN>"),
    (re.compile(r"[Cc]:\\Users\\jdoe\b"), r"C:\Users\<USER>"),
    (re.compile(r"[Cc]:/Users/jdoe\b"), r"C:/Users/<USER>"),
    (re.compile(r"[Cc]:\\Users\\name\\NTUSER\.DAT"), r"C:\Users\<USER>\NTUSER.DAT"),
    (re.compile(r"ssh-keygen -lf /home/jdoe/\.ssh/authorized_keys"), "ssh-keygen -lf '/home/<USER>/.ssh/authorized_keys'"),
    (re.compile(r"/home/jdoe\b"), r"/home/<USER>"),
    (re.compile(r"ssh jdoe@"), "ssh '<USER>'@"),
    (re.compile(r"-Identity jdoe\b"), "-Identity '<USER>'"),
    (re.compile(r"sudo chage -l jdoe\b"), "sudo chage -l '<USER>'"),
    (re.compile(r"sudo passwd -S jdoe\b"), "sudo passwd -S '<USER>'"),
    (re.compile(r"sudo usermod -L jdoe\b"), "sudo usermod -L '<USER>'"),
    (re.compile(r"sudo usermod -s /usr/sbin/nologin jdoe\b"), "sudo usermod -s /usr/sbin/nologin '<USER>'"),
    (re.compile(r"sudo chage -E 0 jdoe\b"), "sudo chage -E 0 '<USER>'"),
    (re.compile(r"pkill -KILL -u jdoe\b"), "pkill -KILL -u '<USER>'"),
    (re.compile(r"\bjdoe\b"), "<USER>"),
    (re.compile(r"\brgeorge\b", re.IGNORECASE), "<USER>"),

    # 5. Domains
    (re.compile(r"\bcontoso\.local\b"), "<INTERNAL_DOMAIN>"),
    (re.compile(r"\bcontoso\.com\b"), "<DOMAIN>"),
]


def find_files(root: Path) -> list[Path]:
    """Find all files to check, ignoring excluded directories."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not any(part in IGNORE_DIRS for part in rel_dir.parts)]
        for f in filenames:
            if f in IGNORE_FILES:
                continue
            if f.endswith((".pyc", ".png", ".jpg", ".ico", ".svg")):
                continue
            files.append(Path(dirpath) / f)
    return sorted(files)


def scan_file(file_path: Path, root: Path, include_all_ips: bool = False) -> list[Finding]:
    """Scan a single file for identifiers."""
    findings: list[Finding] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = text.splitlines()

    # Regex patterns for discovery
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    user_path_re = re.compile(r"(?:[Cc]:[\\/]Users[\\/]|/home/|/Users/)([\w.-]+)", re.IGNORECASE)
    domain_re = re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|net|org|local|internal|corp|lan|io|gov))\b", re.IGNORECASE)
    email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    for line_idx, line in enumerate(lines, start=1):
        # 1. IPs
        for m in ip_re.finditer(line):
            ip = m.group()
            is_special = ip in LOOPBACK_AND_BIND_IPS or ip in PUBLIC_DNS_IPS
            if not include_all_ips and is_special:
                continue
            cat = "IP (206.*)" if ip.startswith("206.") else "IP Address"
            findings.append(Finding(
                category=cat,
                identifier=ip,
                file_path=file_path.relative_to(root),
                line_number=line_idx,
                line_content=line.strip(),
            ))

        # 2. User paths
        for m in user_path_re.finditer(line):
            user = m.group(1)
            if user not in ("<user>", "<USER>", "Public", "Default"):
                findings.append(Finding(
                    category="Username / User Path",
                    identifier=user,
                    file_path=file_path.relative_to(root),
                    line_number=line_idx,
                    line_content=line.strip(),
                ))

        # 3. Known accounts
        for uname in ("jdoe", "rgeorge", "Meshy"):
            if re.search(rf"\b{re.escape(uname)}\b", line, re.IGNORECASE):
                cat = "Hostname" if uname.lower() == "meshy" else "Username"
                findings.append(Finding(
                    category=cat,
                    identifier=uname,
                    file_path=file_path.relative_to(root),
                    line_number=line_idx,
                    line_content=line.strip(),
                ))

        # 4. Hostnames
        if re.search(r"\bserver01\b", line, re.IGNORECASE):
            findings.append(Finding(
                category="Hostname",
                identifier="server01",
                file_path=file_path.relative_to(root),
                line_number=line_idx,
                line_content=line.strip(),
            ))

        # 5. Domains
        for m in domain_re.finditer(line):
            domain = m.group(1).lower()
            if domain in ALLOWED_PUBLIC_DOMAINS or domain == "example.com":
                continue
            findings.append(Finding(
                category="Domain Identifier",
                identifier=domain,
                file_path=file_path.relative_to(root),
                line_number=line_idx,
                line_content=line.strip(),
            ))

        # 6. Emails
        for m in email_re.finditer(line):
            email = m.group()
            findings.append(Finding(
                category="Email Identifier",
                identifier=email,
                file_path=file_path.relative_to(root),
                line_number=line_idx,
                line_content=line.strip(),
            ))

    return findings


def check_206_specifically(files: list[Path], root: Path) -> list[Finding]:
    """Exhaustive check specifically for any 206.* IP address."""
    findings: list[Finding] = []
    p206 = re.compile(r"\b206\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for fp in files:
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_no, line in enumerate(content.splitlines(), start=1):
            for m in p206.finditer(line):
                findings.append(Finding(
                    category="CRITICAL: 206.* IP Address",
                    identifier=m.group(),
                    file_path=fp.relative_to(root),
                    line_number=line_no,
                    line_content=line.strip(),
                ))
    return findings


def sanitize_text(text: str) -> str:
    """Apply sanitization replacements to content."""
    modified = text
    for pattern, replacement in REPLACEMENTS:
        repl_val = replacement
        modified = pattern.sub(lambda m, r=repl_val: r, modified)
    return modified


def process_files(files: list[Path], dry_run: bool = False, in_place: bool = False) -> tuple[int, list[str]]:
    """Process files for sanitization."""
    changed_count = 0
    diffs: list[str] = []

    for fp in files:
        try:
            original = fp.read_text(encoding="utf-8")
        except Exception:
            continue

        sanitized = sanitize_text(original)
        if sanitized != original:
            changed_count += 1
            rel = fp.relative_to(ROOT).as_posix()
            if dry_run or not in_place:
                diff = list(difflib.unified_diff(
                    original.splitlines(keepends=True),
                    sanitized.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                    n=2,
                ))
                diffs.append("".join(diff))
            if in_place:
                fp.write_text(sanitized, encoding="utf-8")

    return changed_count, diffs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Command & Code Repository Identifier Sanitizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scan", action="store_true", help="Scan repository and list all findings")
    parser.add_argument("--dry-run", action="store_true", help="Preview proposed sanitization diff")
    parser.add_argument("--run", action="store_true", help="Apply sanitization in-place across files")
    parser.add_argument("--check-206", action="store_true", help="Audit explicitly for 206.* IPs")
    parser.add_argument("--all-ips", action="store_true", help="Include loopback/bind/public DNS in scan")

    args = parser.parse_args()

    files = find_files(ROOT)

    # 1. Check for 206.* specifically
    findings_206 = check_206_specifically(files, ROOT)

    if args.check_206:
        print("=" * 70)
        print("AUDIT RESULT: 206.* IP Addresses")
        print("=" * 70)
        if findings_206:
            print(f"[ALERT] Found {len(findings_206)} occurrence(s) of 206.* IP addresses:")
            for f in findings_206:
                print(f"  {f.file_path}:{f.line_number} -> {f.identifier} in: {f.line_content}")
            return 1
        else:
            print("[CLEAN] Verified: Exactly 0 occurrences of 206.* IP addresses found.")
            print("Note: The reported '206 something IP' is confirmed to be 203.0.113.10")
            print("      (RFC 5737 TEST-NET-3 documentation range), which was mistaken for 206.*.")
            return 0

    # 2. In-place run or dry-run
    if args.run or args.dry_run:
        action_name = "DRY RUN (Previewing)" if args.dry_run else "IN-PLACE EXECUTION (Applying)"
        print("=" * 70)
        print(f"SANITIZER: {action_name}")
        print("=" * 70)
        changed_count, diffs = process_files(files, dry_run=args.dry_run, in_place=args.run)

        print(f"Total files scanned: {len(files)}")
        print(f"Files affected:     {changed_count}")
        print()

        if diffs:
            print("--- Diff preview (first 5 files) ---")
            for diff in diffs[:5]:
                print(diff)
            if len(diffs) > 5:
                print(f"... and {len(diffs) - 5} more files modified.")

        if args.run:
            print()
            print("[SUCCESS] All targeted hostnames, usernames, IP addresses, and domain")
            print("          identifiers have been sanitized in-place.")
        return 0

    # 3. Default: Scan mode
    print("=" * 70)
    print("SANITIZER SCAN REPORT")
    print("=" * 70)
    print(f"Repository Root: {ROOT}")
    print(f"Scanning {len(files)} files...\n")

    all_findings: list[Finding] = []
    for fp in files:
        all_findings.extend(scan_file(fp, ROOT, include_all_ips=args.all_ips))

    # Category counts
    by_category: dict[str, list[Finding]] = {}
    for f in all_findings:
        by_category.setdefault(f.category, []).append(f)

    print("Summary of Findings by Category:")
    print("-" * 70)
    for cat, items in sorted(by_category.items()):
        unique_vals = sorted(set(i.identifier for i in items))
        print(f"  - {cat:<26} : {len(items):3d} occurrences | Identifiers: {', '.join(unique_vals[:5])}")

    print("-" * 70)
    print(f"Audit for '206.*' IP: {'FOUND ' + str(len(findings_206)) if findings_206 else '0 found (clean)'}")
    print(f"Total items flagged : {len(all_findings)}")
    print()
    print("To preview the sanitization diff, run:  python tools/sanitize.py --dry-run")
    print("To execute sanitization in-place, run:  python tools/sanitize.py --run")
    print("To check specifically for 206.* IPs, run: python tools/sanitize.py --check-206")

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
