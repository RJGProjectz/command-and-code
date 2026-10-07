#!/usr/bin/env python3
"""
Command & Code — Local AI & Grounding Knowledge Indexer
Phase 6 (Intelligent Search & Local AI) Engine

Extracts structured documentation pages, front matter metadata, and code blocks
into an optimized JSONL dataset suitable for:
1. Retrieval-Augmented Generation (RAG) vector embeddings.
2. Local Ollama / LLM prompt context injection.
3. Rapid CLI semantic lookup and cross-platform query generation.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

# Import page extraction from cc tool
sys.path.insert(0, str(ROOT))
try:
    from tools.cc import all_pages, _code_blocks
except ImportError:
    all_pages = None
    _code_blocks = None


def extract_sections(text: str) -> list[dict[str, str]]:
    """Splits markdown content into logical heading sections with code blocks."""
    lines = text.splitlines()
    sections: list[dict[str, str]] = []
    current_title = "Overview"
    current_body: list[str] = []

    for line in lines:
        if line.startswith("#"):
            if current_body:
                sections.append({
                    "title": current_title,
                    "content": "\n".join(current_body).strip()
                })
                current_body = []
            current_title = line.lstrip("#").strip()
        else:
            current_body.append(line)

    if current_body:
        sections.append({
            "title": current_title,
            "content": "\n".join(current_body).strip()
        })

    return sections


def build_ai_index(output_file: Path | None = None) -> list[dict]:
    """Generates the grounded AI knowledge index from documentation pages."""
    if all_pages is None:
        raise RuntimeError("Unable to import tools.cc. Ensure running in repository context.")

    pages = all_pages()
    records: list[dict] = []

    for page in pages:
        raw_text = page.path.read_text(encoding="utf-8")
        
        # Clean YAML front matter from markdown body
        content_body = raw_text
        if raw_text.startswith("---"):
            parts = raw_text.split("---", 2)
            if len(parts) >= 3:
                content_body = parts[2].strip()

        # Extract code blocks
        blocks = []
        if _code_blocks:
            for lang, code, line in _code_blocks(raw_text):
                blocks.append({
                    "language": lang,
                    "line": line,
                    "code": code.strip()
                })

        sections = extract_sections(content_body)

        doc_record = {
            "id": f"cc://{page.rel}",
            "title": page.title,
            "type": page.type,
            "path": f"docs/{page.rel}",
            "platforms": page.meta.get("platforms", []),
            "languages": page.meta.get("languages", []),
            "tasks": page.meta.get("tasks", []),
            "category": page.meta.get("category", ""),
            "summary": sections[0]["content"][:300] if sections else "",
            "sections": sections,
            "code_blocks": blocks,
            "total_code_blocks": len(blocks)
        }
        records.append(doc_record)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return records


def main() -> int:
    output_path = ROOT / "site" / "ai_knowledge_index.jsonl"
    print(f"Indexing Command & Code documentation for Local AI grounding...")
    records = build_ai_index(output_file=output_path)
    print(f"Successfully indexed {len(records)} pages.")
    print(f"Exported grounded index to: {output_path} ({output_path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
