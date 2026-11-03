#!/usr/bin/env python3
"""Command & Code — PDF Book Ingest Pipeline.

Extracts text from every PDF in --pdf-dir, splits each page into
512-token sliding-window chunks (64-token overlap), embeds with Ollama
(nomic-embed-text), and persists to a local ChromaDB 'books' collection.
Writes an NDJSON manifest alongside the database.

Usage:
    python tools/pdf_ingest.py [--pdf-dir "PDF's"] [--db-dir data/chromadb/books]
                               [--model nomic-embed-text] [--chunk-size 512]
                               [--overlap 64] [--force-reingest]

security_domain: Knowledge Management
Author: RJGProjectz
Created: 2026-11-03T00:00:00Z
Last Modified: 2026-11-03T00:00:00Z
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _clean_title(filename: str) -> str:
    """Convert a PDF filename to a human-readable title-cased string."""
    stem = Path(filename).stem
    # Remove common copy-of / duplicate suffixes before title-casing
    stem = re.sub(r"\s*[\(\[]?copy[\)\]]?.*$", "", stem, flags=re.IGNORECASE)
    stem = re.sub(r"\s*[\(\[]?\d+[\)\]]?\s*$", "", stem)
    stem = re.sub(r"[_\-]+", " ", stem)
    return re.sub(r"\s+", " ", stem).strip().title()


def _sliding_chunks(tokens: list[str], chunk_size: int, overlap: int) -> list[list[str]]:
    """Yield sliding-window token chunks; last partial chunk is included."""
    if not tokens:
        return []
    step = max(1, chunk_size - overlap)
    out: list[list[str]] = []
    start = 0
    while start < len(tokens):
        chunk = tokens[start: start + chunk_size]
        out.append(chunk)
        if start + chunk_size >= len(tokens):
            break
        start += step
    return out


def _embed(text: str, model: str, host: str) -> list[float]:
    """Fetch an embedding vector from the Ollama /api/embeddings endpoint."""
    url = f"{host}/api/embeddings"
    payload = json.dumps({"model": model, "prompt": text}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())["embedding"]


def _already_ingested(collection) -> set[str]:
    """Return filenames present in the ChromaDB collection (skip-check)."""
    try:
        result = collection.get(include=["metadatas"])
        return {m["filename"] for m in result["metadatas"] if m.get("filename")}
    except Exception:
        return set()


def ingest_pdfs(
    pdf_dir: Path,
    db_dir: Path,
    model: str,
    host: str,
    chunk_size: int,
    overlap: int,
    force_reingest: bool,
) -> None:
    try:
        import fitz  # PyMuPDF
    except ImportError:
        sys.exit("[!] PyMuPDF not installed.  Run: pip install pymupdf")

    try:
        import chromadb
    except ImportError:
        sys.exit("[!] chromadb not installed.  Run: pip install chromadb")

    pdfs = sorted(pdf_dir.glob("*.pdf"))
    if not pdfs:
        print(f"[!] No PDF files found in {pdf_dir}")
        return

    db_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = db_dir.parent / "books_manifest.ndjson"

    client = chromadb.PersistentClient(path=str(db_dir))
    collection = client.get_or_create_collection(
        name="books",
        metadata={"hnsw:space": "cosine"},
    )

    already = set() if force_reingest else _already_ingested(collection)
    total_books = total_pages = total_chunks = 0
    new_manifest_lines: list[str] = []

    for idx, pdf_path in enumerate(pdfs, 1):
        filename = pdf_path.name
        title = _clean_title(filename)

        if filename in already:
            print(f"[{idx}/{len(pdfs)}] {title} — skipped (already ingested; use --force-reingest to re-embed)")
            continue

        try:
            doc = fitz.open(str(pdf_path))
        except Exception as exc:
            print(f"[{idx}/{len(pdfs)}] {title} — ERROR opening: {exc}")
            continue

        n_pages = len(doc)
        ids: list[str] = []
        embeddings: list[list[float]] = []
        documents: list[str] = []
        metadatas: list[dict] = []

        for page_idx in range(n_pages):
            page_text = doc.load_page(page_idx).get_text("text").strip()
            if not page_text:
                continue
            for chunk_idx, token_chunk in enumerate(_sliding_chunks(page_text.split(), chunk_size, overlap)):
                chunk_text = " ".join(token_chunk)
                try:
                    vec = _embed(chunk_text, model, host)
                except Exception as exc:
                    print(f"  [!] Embed failed (page {page_idx + 1}, chunk {chunk_idx}): {exc}")
                    continue
                ids.append(f"{filename}::p{page_idx + 1}::c{chunk_idx}")
                embeddings.append(vec)
                documents.append(chunk_text)
                metadatas.append({
                    "book_title": title,
                    "filename": filename,
                    "page_num": page_idx + 1,
                    "chunk_idx": chunk_idx,
                })

        doc.close()

        # Upsert in batches to avoid memory spikes on large books
        batch_size = 500
        for start in range(0, len(ids), batch_size):
            collection.upsert(
                ids=ids[start: start + batch_size],
                embeddings=embeddings[start: start + batch_size],
                documents=documents[start: start + batch_size],
                metadatas=metadatas[start: start + batch_size],
            )

        n_chunks = len(ids)
        ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_manifest_lines.append(json.dumps({
            "book_title": title,
            "filename": filename,
            "pages": n_pages,
            "chunks": n_chunks,
            "ingested_at": ingested_at,
        }, ensure_ascii=False))

        total_books += 1
        total_pages += n_pages
        total_chunks += n_chunks
        print(f"[{idx}/{len(pdfs)}] {title} — {n_pages} pages, {n_chunks} chunks")

    if new_manifest_lines:
        with manifest_path.open("a", encoding="utf-8") as fh:
            for line in new_manifest_lines:
                fh.write(line + "\n")

    print(f"\nDone: {total_books} new books, {total_pages} pages, {total_chunks} chunks")
    if new_manifest_lines:
        print(f"Manifest: {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Command & Code — PDF Book Ingest Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--pdf-dir", type=Path, default=ROOT / "PDF's",
                        help="Directory containing PDF files")
    parser.add_argument("--db-dir", type=Path, default=ROOT / "data" / "chromadb" / "books",
                        help="ChromaDB persistent storage path")
    parser.add_argument("--model", default="nomic-embed-text",
                        help="Ollama embedding model")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama API endpoint")
    parser.add_argument("--chunk-size", type=int, default=512,
                        help="Tokens per chunk (whitespace-split)")
    parser.add_argument("--overlap", type=int, default=64,
                        help="Token overlap between adjacent chunks")
    parser.add_argument("--force-reingest", action="store_true",
                        help="Re-embed and overwrite books that are already stored")
    args = parser.parse_args()

    if not args.pdf_dir.is_dir():
        sys.exit(f"[!] PDF directory not found: {args.pdf_dir}")
    if args.chunk_size <= args.overlap:
        sys.exit("[!] --chunk-size must be greater than --overlap")

    ingest_pdfs(
        pdf_dir=args.pdf_dir,
        db_dir=args.db_dir,
        model=args.model,
        host=args.host,
        chunk_size=args.chunk_size,
        overlap=args.overlap,
        force_reingest=args.force_reingest,
    )


if __name__ == "__main__":
    main()
