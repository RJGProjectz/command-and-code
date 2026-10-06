#!/usr/bin/env python3
"""Command & Code Local CLI Lookup Tool

Search and inspect knowledge nodes, workflows, detections, and copy-ready syntax
directly from the terminal without a web browser.
"""

import argparse
import pathlib
import sys
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

def load_pages():
    pages = []
    for p in DOCS.rglob("*.md"):
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        meta = {}
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
            "title": meta.get("title", p.stem),
            "type": meta.get("type", "unknown"),
            "platforms": meta.get("platforms", []),
            "languages": meta.get("languages", []),
            "tasks": meta.get("tasks", []),
            "tags": meta.get("tags", []),
            "meta": meta,
            "body": body
        })
    return pages

def search_pages(query, platform=None, language=None, task=None):
    pages = load_pages()
    results = []
    q_lower = query.lower() if query else ""

    for p in pages:
        if platform and platform.lower() not in [str(x).lower() for x in p["platforms"]]:
            continue
        if language and language.lower() not in [str(x).lower() for x in p["languages"]]:
            continue
        if task and task.lower() not in [str(x).lower() for x in p["tasks"]]:
            continue

        score = 0
        if q_lower:
            if q_lower in str(p["title"]).lower():
                score += 10
            if any(q_lower in str(t).lower() for t in p["tags"]):
                score += 5
            if any(q_lower in str(pl).lower() for pl in p["platforms"]):
                score += 3
            if any(q_lower in str(l).lower() for l in p["languages"]):
                score += 3
            if any(q_lower in str(tk).lower() for tk in p["tasks"]):
                score += 3
            if q_lower in p["body"].lower():
                score += 1
            if score == 0:
                continue
        else:
            score = 1

        results.append((score, p))

    results.sort(key=lambda x: (x[0], x[1]["title"]), reverse=True)
    return [r[1] for r in results]

def main():
    parser = argparse.ArgumentParser(description="Command & Code Offline Terminal Lookup")
    parser.add_argument("query", nargs="?", default="", help="Search keywords (e.g. 'failed logons', 'isolate')")
    parser.add_argument("-p", "--platform", help="Filter by platform (e.g. Windows, Linux, Splunk)")
    parser.add_argument("-l", "--language", help="Filter by language (e.g. PowerShell, Bash, SPL)")
    parser.add_argument("-t", "--task", help="Filter by task (e.g. Investigation, Hardening)")
    parser.add_argument("-c", "--cat", help="Show full content of matching page path", metavar="PAGE_PATH")
    parser.add_argument("-n", "--limit", type=int, default=10, help="Max results to display")
    args = parser.parse_args()

    if args.cat:
        target = DOCS / args.cat
        if not target.exists():
            print(f"Error: Path '{args.cat}' does not exist in docs/", file=sys.stderr)
            sys.exit(1)
        print(target.read_text(encoding="utf-8"))
        return

    hits = search_pages(args.query, platform=args.platform, language=args.language, task=args.task)
    if not hits:
        print(f"No entries found matching query='{args.query}'")
        return

    print(f"\n[Command & Code] Found {len(hits)} matching entries (showing top {min(len(hits), args.limit)}):\n")
    for i, p in enumerate(hits[:args.limit], 1):
        plats = ", ".join(p["platforms"]) or "-"
        langs = ", ".join(p["languages"]) or "-"
        tasks = ", ".join(p["tasks"]) or "-"
        print(f" {i:2d}. {p['title']}")
        print(f"     Path:      docs/{p['path']}")
        print(f"     Type:      {p['type']} | Platforms: {plats} | Languages: {langs}")
        print(f"     Tasks:     {tasks}")
        print()

    print("Tip: View full document content directly with:")
    print(f"     python tools/lookup.py --cat {hits[0]['path']}\n")

if __name__ == "__main__":
    main()
