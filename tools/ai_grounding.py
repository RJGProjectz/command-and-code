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
import math
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


STOPWORDS = frozenset(
    "the and for are was were who what when where which how why that this with from into onto out "
    "has have had does did not can could should would will all any some its it's them they their "
    "there then than our your you see find show get list check someone something user users".split()
)

# Per-field weight for each query term found in that field (once per field, not per occurrence).
FIELD_WEIGHTS = {
    "title": 15.0,
    "path": 10.0,
    "tags": 10.0,
    "platforms": 8.0,
    "languages": 8.0,
    "tasks": 6.0,
    "summary": 3.0,
    "body": 2.0,
    "code": 2.0,
}

_SUFFIXES = ("ings", "ing", "ions", "ion", "ies", "es", "ed", "ly", "s", "e")


def stem(word: str) -> str:
    """Strips one common English suffix so isolate/isolation and deleted/deletion match."""
    for suffix in _SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)] + ("y" if suffix == "ies" else "")
    return word


def words(text: str) -> set[str]:
    """Lowercase stemmed word set of a text."""
    return {stem(w) for w in re.findall(r"[a-z0-9]+", text.lower())}


def query_terms(query: str) -> list[str]:
    """Stemmed query terms: words longer than 2 chars (or short ones with a digit, e.g. s3), minus stopwords."""
    terms = []
    for w in re.findall(r"[a-z0-9]+", query.lower()):
        if w in STOPWORDS or (len(w) <= 2 and not any(c.isdigit() for c in w)):
            continue
        t = stem(w)
        if t not in terms:
            terms.append(t)
    return terms


def record_fields(record: dict) -> dict[str, set[str]]:
    """Stemmed word sets per scored field of an index record."""
    sections = record.get("sections", [])
    return {
        "title": words(record.get("title", "")),
        "path": words(record.get("path", "").replace("docs/", "", 1)),
        "tags": words(" ".join(str(t) for t in record.get("tags", []))),
        "platforms": words(" ".join(str(p) for p in record.get("platforms", []))),
        "languages": words(" ".join(str(l) for l in record.get("languages", []))),
        "tasks": words(" ".join(str(t) for t in record.get("tasks", []))),
        "summary": words(record.get("summary", "")),
        "body": words(" ".join(f"{s.get('title', '')} {s.get('content', '')}" for s in sections)),
        "code": words(" ".join(b.get("code", "") for b in record.get("code_blocks", []))),
    }


def term_weights(all_fields: list[dict[str, set[str]]]) -> dict[str, float]:
    """Inverse document frequency per term, so rare words (ransomware, mfa) outweigh common ones."""
    n = len(all_fields)
    df: dict[str, int] = {}
    for fields in all_fields:
        for term in set().union(*fields.values()):
            df[term] = df.get(term, 0) + 1
    return {term: math.log((n + 1) / (count + 1)) + 1.0 for term, count in df.items()}


def score_fields(query: str, fields: dict[str, set[str]], title: str = "", idf: dict[str, float] | None = None) -> float:
    terms = query_terms(query)
    if not terms:
        return 0.0

    score = 0.0
    # Full query exact match boost
    if len(terms) > 1 and " ".join(query.lower().split()) in title.lower():
        score += 50.0

    for term in terms:
        weight = idf.get(term, 1.0) if idf else 1.0
        score += weight * sum(w for name, w in FIELD_WEIGHTS.items() if term in fields[name])
    return score


def score_record(query: str, record: dict, idf: dict[str, float] | None = None) -> float:
    """Calculates relevance score using stemmed multi-field term matching, optionally IDF-weighted."""
    return score_fields(query, record_fields(record), record.get("title", ""), idf)


def search(query: str, top_k: int = 5) -> list[tuple[dict, float]]:
    """Retrieves top scoring records from knowledge index."""
    records = load_index()
    all_fields = [record_fields(r) for r in records]
    idf = term_weights(all_fields)
    scored = []
    for r, fields in zip(records, all_fields):
        s = score_fields(query, fields, r.get("title", ""), idf)
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


def query_ollama(prompt: str, model: str = "llama3.2", host: str = "http://localhost:11434", timeout: int = 10) -> str | None:
    """Attempts to query a local Ollama instance if available."""
    url = f"{host}/api/generate"
    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
