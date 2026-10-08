#!/usr/bin/env python3
"""Command & Code Terminal Companion CLI (cc)

Fast, offline operational terminal tool to search the knowledge base,
view runbooks, extract copy-ready commands, and execute scripts directly
from your active PowerShell or Bash prompt.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

import yaml

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SCRIPTS = ROOT / "scripts"

# ANSI Terminal Colors
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def c_bold(text: str) -> str: return color(text, "1")
def c_amber(text: str) -> str: return color(text, "33")
def c_cyan(text: str) -> str: return color(text, "36")
def c_green(text: str) -> str: return color(text, "32")
def c_red(text: str) -> str: return color(text, "31")
def c_dim(text: str) -> str: return color(text, "90")
def c_magenta(text: str) -> str: return color(text, "35")

def banner() -> None:
    print(c_bold(c_amber("+-------------------------------------------------------------+")))
    print(c_bold(c_amber("|  COMMAND & CODE  --  Operational Terminal Companion (cc)    |")))
    print(c_bold(c_amber("+-------------------------------------------------------------+")))

def load_pages() -> List[Dict[str, Any]]:
    pages = []
    for p in sorted(DOCS.rglob("*.md")):
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        meta: Dict[str, Any] = {}
        body = text
        if text.startswith("---\n"):
            end = text.find("\n---\n", 4)
            if end != -1:
                try:
                    meta = yaml.safe_load(text[4:end]) or {}
                except Exception:
                    meta = {}
                body = text[end + 5:]
        pages.append({
            "path": p.relative_to(DOCS).as_posix(),
            "full_path": p,
            "title": str(meta.get("title") or p.stem),
            "type": str(meta.get("type", "entry")),
            "platforms": [str(x) for x in meta.get("platforms", [])] if isinstance(meta.get("platforms"), list) else [],
            "languages": [str(x) for x in meta.get("languages", [])] if isinstance(meta.get("languages"), list) else [],
            "tasks": [str(x) for x in meta.get("tasks", [])] if isinstance(meta.get("tasks"), list) else [],
            "tags": [str(x) for x in meta.get("tags", [])] if isinstance(meta.get("tags"), list) else [],
            "meta": meta,
            "body": body
        })
    return pages

def search_pages(query: str, platform: Optional[str] = None, language: Optional[str] = None, task: Optional[str] = None) -> List[Tuple[int, Dict[str, Any]]]:
    pages = load_pages()
    results = []
    q_lower = query.lower() if query else ""

    for p in pages:
        if platform and platform.lower() not in [x.lower() for x in p["platforms"]]:
            continue
        if language and language.lower() not in [x.lower() for x in p["languages"]]:
            continue
        if task and task.lower() not in [x.lower() for x in p["tasks"]]:
            continue

        score = 0
        if q_lower:
            title_lower = p["title"].lower()
            path_lower = p["path"].lower()
            if q_lower == title_lower:
                score += 50
            elif q_lower in title_lower:
                score += 25
            if q_lower in path_lower:
                score += 15
            for tag in p["tags"]:
                if q_lower == tag.lower():
                    score += 20
                elif q_lower in tag.lower():
                    score += 10
            for pl in p["platforms"]:
                if q_lower in pl.lower():
                    score += 5
            for lang in p["languages"]:
                if q_lower in lang.lower():
                    score += 5
            for t in p["tasks"]:
                if q_lower in t.lower():
                    score += 5
            if q_lower in p["body"].lower():
                score += 2
            if score == 0:
                continue
        else:
            score = 1

        results.append((score, p))

    results.sort(key=lambda x: (x[0], x[1]["title"]), reverse=True)
    return results

def extract_code_blocks(body: str) -> List[Tuple[str, str]]:
    """Extract (language, code) tuples from fenced code blocks."""
    blocks = []
    pattern = re.compile(r"```([a-zA-Z0-9_\-]+)?\n(.*?)```", re.DOTALL)
    for match in pattern.finditer(body):
        lang = match.group(1) or "text"
        code = match.group(2).strip()
        if code:
            blocks.append((lang, code))
    return blocks

def copy_to_clipboard(text: str) -> bool:
    """Copy text to system clipboard across Windows, macOS, and Linux."""
    # 1. PowerShell Set-Clipboard (Windows Native)
    if sys.platform.startswith("win"):
        try:
            ps_proc = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-Command", "$input | Set-Clipboard"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8"
            )
            ps_proc.communicate(input=text)
            if ps_proc.returncode == 0:
                return True
        except Exception:
            pass

        # Fallback to clip.exe
        try:
            p = subprocess.Popen("clip", stdin=subprocess.PIPE, shell=True)
            p.communicate(input=text.encode("utf-8"))
            if p.returncode == 0:
                return True
        except Exception:
            pass

    # 2. macOS pbcopy
    if shutil.which("pbcopy"):
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"))
            if p.returncode == 0:
                return True
        except Exception:
            pass

    # 3. Linux xclip or wl-copy
    if shutil.which("wl-copy"):
        try:
            p = subprocess.Popen(["wl-copy"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"))
            if p.returncode == 0:
                return True
        except Exception:
            pass

    if shutil.which("xclip"):
        try:
            p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"))
            if p.returncode == 0:
                return True
        except Exception:
            pass

    return False

# =========================================================================
# CLI Commands
# =========================================================================

def cmd_find(args: argparse.Namespace) -> None:
    query = " ".join(args.query).strip()
    results = search_pages(query, platform=args.platform, language=args.language, task=args.task)

    if not results:
        print(c_red(f"No entries found matching query: '{query}'"))
        return

    total = len(results)
    limit = min(total, args.limit)
    print(c_dim(f"Found {total} matching entries (showing top {limit}):\n"))

    for i, (score, p) in enumerate(results[:limit], 1):
        plats = ", ".join(p["platforms"]) or "-"
        langs = ", ".join(p["languages"]) or "-"
        tasks = ", ".join(p["tasks"]) or "-"
        print(f" {c_bold(c_amber(f'{i:2d}.'))} {c_bold(p['title'])}")
        print(f"     {c_dim('Path:')}      docs/{p['path']}")
        print(f"     {c_dim('Meta:')}      {c_cyan(p['type'])} | {c_dim('Platforms:')} {plats} | {c_dim('Languages:')} {langs}")
        print(f"     {c_dim('Tasks:')}     {tasks}")
        print()

    best = results[0][1]["path"]
    print(c_dim("-------------------------------------------------------------"))
    print(c_dim("Quick Actions:"))
    print(f"  View guide:    {c_cyan(f'cc view {best}')}")
    print(f"  View code:     {c_cyan(f'cc view {best} --code')}")
    print(f"  Copy syntax:   {c_cyan(f'cc copy {best}')}\n")

def cmd_view(args: argparse.Namespace) -> None:
    target = args.target
    matched_page = None

    # Try direct path resolution
    exact_path = DOCS / target if not target.startswith("docs/") else ROOT / target
    if exact_path.is_file():
        text = exact_path.read_text(encoding="utf-8")
        title = exact_path.stem
        body = text
        if text.startswith("---\n"):
            end = text.find("\n---\n", 4)
            if end != -1:
                body = text[end + 5:]
        matched_page = {"title": title, "path": target, "body": body}
    else:
        # Fuzzy search best match
        hits = search_pages(target)
        if hits:
            matched_page = hits[0][1]

    if not matched_page:
        print(c_red(f"Error: Could not find page matching '{target}'"))
        return

    print(f"\n{c_bold(c_amber('=== ' + matched_page['title'] + ' ==='))}")
    print(c_dim(f"Path: docs/{matched_page['path']}\n"))

    blocks = extract_code_blocks(matched_page["body"])

    if args.code:
        if not blocks:
            print(c_dim("No executable code blocks found in this entry."))
            return
        print(c_green(f"Extracted {len(blocks)} code blocks:\n"))
        for idx, (lang, code) in enumerate(blocks, 1):
            print(c_bold(c_cyan(f"+-- [Block {idx}] ({lang}) --------------------------------------")))
            for line in code.splitlines():
                print(f"| {line}")
            print(c_bold(c_cyan(f"+-----------------------------------------------------------\n")))
        print(c_dim(f"Tip: Copy a block directly with: cc copy {matched_page['path']} --block 1\n"))
    else:
        print(matched_page["body"])

def cmd_copy(args: argparse.Namespace) -> None:
    target = args.target
    hits = search_pages(target)
    if not hits:
        print(c_red(f"Error: No entry found matching '{target}'"))
        return

    page = hits[0][1]
    blocks = extract_code_blocks(page["body"])
    if not blocks:
        print(c_red(f"Error: No code blocks found in '{page['title']}'"))
        return

    block_idx = args.block - 1
    if block_idx < 0 or block_idx >= len(blocks):
        print(c_red(f"Error: Block {args.block} out of range (available: 1 to {len(blocks)})"))
        return

    lang, code = blocks[block_idx]
    copied = copy_to_clipboard(code)

    if copied:
        print(c_green(f"[OK] Copied Block {args.block} ({lang}) from '{page['title']}' to clipboard!"))
    else:
        print(c_amber(f"Notice: Clipboard access unavailable in current terminal. Syntax printed below:"))
        print(code)

def cmd_scripts(args: argparse.Namespace) -> None:
    filter_q = args.filter.lower() if args.filter else ""
    found = []

    for folder in [SCRIPTS / "powershell", SCRIPTS / "bash", SCRIPTS / "python"]:
        if not folder.exists():
            continue
        lang_type = folder.name
        for s in sorted(folder.iterdir()):
            if s.is_file() and not s.name.startswith("__"):
                if filter_q and filter_q not in s.name.lower():
                    continue
                found.append((lang_type, s.name, s))

    print(c_dim(f"\nCataloged Automation Scripts ({len(found)} scripts found):\n"))
    for lang, name, path in found:
        print(f"  {c_cyan(f'[{lang.upper()}]')} {c_bold(name)}")
        print(f"      {c_dim('Path:')} scripts/{lang}/{name}")

    print(c_dim("\nRun any script with: cc run <script-name> [args...]\n"))

def cmd_run(args: argparse.Namespace) -> None:
    script_target = args.script.lower()
    matches = []

    for folder in [SCRIPTS / "powershell", SCRIPTS / "bash", SCRIPTS / "python"]:
        if not folder.exists():
            continue
        for s in folder.iterdir():
            if s.is_file() and (script_target in s.name.lower()):
                matches.append(s)

    if not matches:
        print(c_red(f"Error: No script found matching '{args.script}' in scripts/"))
        return

    target_script = matches[0]
    print(c_bold(c_amber(f"Executing: scripts/{target_script.parent.name}/{target_script.name}")))

    ext = target_script.suffix.lower()
    remaining_args = args.args

    if ext == ".ps1":
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(target_script)] + remaining_args
    elif ext == ".sh":
        cmd = ["bash", str(target_script)] + remaining_args
    elif ext == ".py":
        cmd = [sys.executable, str(target_script)] + remaining_args
    else:
        print(c_red(f"Unsupported script extension: {ext}"))
        return

    try:
        subprocess.run(cmd)
    except Exception as exc:
        print(c_red(f"Execution failed: {exc}"))

def cmd_doctor(_args: argparse.Namespace) -> None:
    banner()
    print(c_bold("\nSystem & Environment Audit:\n"))

    print(f"  Python Version:     {sys.version.split()[0]} ({sys.executable})")
    print(f"  Operating System:   {sys.platform}")
    print(f"  Workspace Root:     {ROOT}")

    # Check git
    git_status = "Available" if shutil.which("git") else "Missing"
    print(f"  Git CLI:            {git_status}")

    # Check PowerShell
    ps_path = shutil.which("pwsh") or shutil.which("powershell")
    print(f"  PowerShell:         {ps_path or 'Not found'}")

    # Total pages and scripts
    pages = load_pages()
    total_scripts = sum(1 for _ in SCRIPTS.rglob("*") if _.is_file())
    print(f"  Indexed Pages:      {c_green(str(len(pages)))} markdown entries")
    print(f"  Automation Scripts: {c_green(str(total_scripts))} production scripts")

    # CI check test
    print(f"\n  Running repository check verification...")
    res = subprocess.run([sys.executable, str(ROOT / "tools" / "cc.py"), "validate"], capture_output=True, text=True)
    if res.returncode == 0:
        print(c_green("  [OK] cc.py validation: All frontmatter and schemas 100% compliant."))
    else:
        print(c_red(f"  [FAIL] cc.py validation reported issues:\n{res.stdout}"))

    print()

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cc",
        description="Command & Code Terminal Companion CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  cc find listening ports\n"
               "  cc view ransomware-host-isolation --code\n"
               "  cc copy ransomware-host-isolation --block 1\n"
               "  cc scripts vpn\n"
               "  cc run FUNC_PS_TEST_VPN_CONNECTION\n"
               "  cc doctor\n"
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # find
    p_find = subparsers.add_parser("find", aliases=["search"], help="Search knowledge base entries")
    p_find.add_argument("query", nargs="*", default=[], help="Keywords to search")
    p_find.add_argument("-p", "--platform", help="Filter by platform")
    p_find.add_argument("-l", "--language", help="Filter by language")
    p_find.add_argument("-t", "--task", help="Filter by task")
    p_find.add_argument("-n", "--limit", type=int, default=8, help="Max results (default: 8)")
    p_find.set_defaults(func=cmd_find)

    # view
    p_view = subparsers.add_parser("view", aliases=["cat"], help="View document or extract code blocks")
    p_view.add_argument("target", help="Document path or search query")
    p_view.add_argument("-c", "--code", action="store_true", help="Extract and display code blocks only")
    p_view.set_defaults(func=cmd_view)

    # copy
    p_copy = subparsers.add_parser("copy", help="Copy command block directly to system clipboard")
    p_copy.add_argument("target", help="Document path or search query")
    p_copy.add_argument("-b", "--block", type=int, default=1, help="Code block index to copy (default: 1)")
    p_copy.set_defaults(func=cmd_copy)

    # scripts
    p_scripts = subparsers.add_parser("scripts", help="List cataloged production scripts")
    p_scripts.add_argument("filter", nargs="?", default="", help="Optional script name filter")
    p_scripts.set_defaults(func=cmd_scripts)

    # run
    p_run = subparsers.add_parser("run", help="Execute an automation script from scripts/")
    p_run.add_argument("script", help="Script name or substring match")
    p_run.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to the script")
    p_run.set_defaults(func=cmd_run)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Audit local environment and repository health")
    p_doc.set_defaults(func=cmd_doctor)

    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        sys.exit(0)

    # If first argument is not a known command, default to 'find'
    known_commands = {"find", "search", "view", "cat", "copy", "scripts", "run", "doctor", "-h", "--help"}
    if sys.argv[1] not in known_commands and not sys.argv[1].startswith("-"):
        sys.argv.insert(1, "find")

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
