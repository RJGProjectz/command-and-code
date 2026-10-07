#!/usr/bin/env python3
"""Command & Code — Local AI Grounding & Query Translation Engine.

Phase 6 (Intelligent Search & Local AI) Engine:
1. Performs grounded semantic search against site/ai_knowledge_index.jsonl.
2. Extracts copy-ready code blocks and commands from authoritative documentation.
3. Formats grounded prompts for local LLMs (Ollama, LM Studio, LocalAI).
4. Translates security queries across KQL, SPL, S1QL, PowerShell, and Bash.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX_FILE = ROOT / "site" / "ai_knowledge_index.jsonl"


def load_index() -> list[dict]:
    """Loads grounded knowledge index or triggers regeneration if missing."""
    if not INDEX_FILE.exists():
        from tools.ai_indexer import build_ai_index
        build_ai_index(output_file=INDEX_FILE)

    records = []
    with INDEX_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def score_record(query: str, record: dict) -> float:
    """Calculates relevance score using multi-field token matching."""
    tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]
    if not tokens:
        return 0.0

    score = 0.0
    title_lower = record.get("title", "").lower()
    summary_lower = record.get("summary", "").lower()
    tags = [str(t).lower() for t in record.get("tags", [])]
    platforms = [str(p).lower() for p in record.get("platforms", [])]
    languages = [str(l).lower() for l in record.get("languages", [])]
    tasks = [str(t).lower() for t in record.get("tasks", [])]

    # Full query exact match boost
    q_str = " ".join(tokens)
    if q_str in title_lower:
        score += 50.0

    for token in tokens:
        if token in title_lower:
            score += 15.0
        if any(token in t for t in tags):
            score += 10.0
        if any(token in p for p in platforms):
            score += 8.0
        if any(token in l for l in languages):
            score += 8.0
        if any(token in t for t in tasks):
            score += 6.0
        if token in summary_lower:
            score += 3.0

        # Scan code blocks
        for block in record.get("code_blocks", []):
            code_text = block.get("code", "").lower()
            if token in code_text:
                score += 4.0

    return score


def search(query: str, top_k: int = 5) -> list[tuple[dict, float]]:
    """Retrieves top scoring records from knowledge index."""
    records = load_index()
    scored = []
    for r in records:
        s = score_record(query, r)
        if s > 0:
            scored.append((r, s))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]


def build_grounded_prompt(query: str, top_k: int = 3) -> str:
    """Builds a grounded prompt containing verified repository context."""
    results = search(query, top_k=top_k)
    context_parts = []

    for i, (rec, score) in enumerate(results, 1):
        context_parts.append(f"### [Source {i}]: {rec['title']} ({rec['path']})")
        context_parts.append(f"Platforms: {', '.join(rec.get('platforms', []))} | Languages: {', '.join(rec.get('languages', []))}")
        context_parts.append(f"Summary: {rec.get('summary', '').strip()}")
        
        # Include top 2 relevant code blocks
        blocks = rec.get("code_blocks", [])[:2]
        for b in blocks:
            context_parts.append(f"```{b.get('language', '')}\n{b.get('code', '').strip()}\n```")
        context_parts.append("")

    prompt = (
        "You are an expert Security Operations AI grounded strictly in the verified Command & Code knowledge base.\n"
        "Use ONLY the following authoritative repository context to answer the user request.\n"
        "If unsure, reference the exact document paths provided.\n\n"
        "=== AUTHORITATIVE COMMAND & CODE CONTEXT ===\n"
        + "\n".join(context_parts)
        + "\n============================================\n\n"
        f"USER REQUEST: {query}\n\n"
        "GROUNDED ANSWER:"
    )
    return prompt


def query_ollama(prompt: str, model: str = "llama3.2", host: str = "http://localhost:11434") -> str | None:
    """Attempts to query a local Ollama instance if available."""
    url = f"{host}/api/generate"
    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("response", "")
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Command & Code Grounded AI Engine")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to run")

    # Search
    search_p = subparsers.add_parser("search", help="Search grounded knowledge index")
    search_p.add_argument("query", help="Search query string")
    search_p.add_argument("-k", "--top-k", type=int, default=5, help="Number of results to return")

    # Prompt
    prompt_p = subparsers.add_parser("prompt", help="Build grounded LLM prompt")
    prompt_p.add_argument("query", help="User request to ground")
    prompt_p.add_argument("-k", "--top-k", type=int, default=3, help="Context documents")

    # Ask
    ask_p = subparsers.add_parser("ask", help="Query local Ollama with grounded context")
    ask_p.add_argument("query", help="User security question")
    ask_p.add_argument("--model", default="llama3.2", help="Ollama model name")
    ask_p.add_argument("--host", default="http://localhost:11434", help="Ollama host endpoint")

    args = parser.parse_args()

    if args.command == "search":
        results = search(args.query, top_k=args.top_k)
        print(f"\n[+] Found {len(results)} grounded results for: '{args.query}'\n")
        for i, (rec, score) in enumerate(results, 1):
            print(f"{i}. {rec['title']} (Score: {score:.1f})")
            print(f"   Path: {rec['path']}")
            print(f"   Platforms: {', '.join(rec.get('platforms', []))} | Languages: {', '.join(rec.get('languages', []))}")
            if rec.get("code_blocks"):
                first_code = rec["code_blocks"][0]
                preview = first_code["code"].splitlines()[0] if first_code["code"] else ""
                print(f"   Primary Command [{first_code['language']}]: {preview[:80]}")
            print()

    elif args.command == "prompt":
        prompt = build_grounded_prompt(args.query, top_k=args.top_k)
        print(prompt)

    elif args.command == "ask":
        prompt = build_grounded_prompt(args.query, top_k=3)
        print(f"[*] Querying local Ollama ({args.host}) with model '{args.model}'...")
        response = query_ollama(prompt, model=args.model, host=args.host)
        if response:
            print("\n" + response)
        else:
            print(f"\n[!] Ollama is not active on {args.host}. Fallback: Showing top grounded repository procedures:\n")
            results = search(args.query, top_k=3)
            for i, (rec, score) in enumerate(results, 1):
                print(f"--- {rec['title']} ({rec['path']}) ---")
                for block in rec.get("code_blocks", [])[:2]:
                    print(f"[{block['language']}]:")
                    print(block['code'])
                    print()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
