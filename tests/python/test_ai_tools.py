"""Tests for the local-AI tooling: tools/ai_indexer.py and tools/ai_grounding.py.

security_domain: AI Systems
Author: RJGProjectz
Created: 2026-10-11T19:30:00Z
"""
import json

from tools import ai_grounding, ai_indexer

RECORDS = [
    {
        "title": "Kerberoasting Hunt",
        "path": "tasks/kerberoasting-hunt.md",
        "summary": "Find RC4 service ticket requests.",
        "tags": ["kerberos"],
        "platforms": ["Windows"],
        "languages": ["PowerShell"],
        "tasks": ["Threat Hunting"],
        "code_blocks": [{"language": "powershell", "code": "Get-WinEvent -FilterHashtable @{Id=4769}"}],
    },
    {
        "title": "Listening Ports",
        "path": "platforms/linux-ports.md",
        "summary": "Show sockets in LISTEN state.",
        "tags": [],
        "platforms": ["Linux"],
        "languages": ["Bash"],
        "tasks": ["Incident Response"],
        "code_blocks": [{"language": "bash", "code": "ss -tlnp"}],
    },
]


def test_extract_sections_splits_on_headings():
    sections = ai_indexer.extract_sections("intro\n# One\na\n## Two\nb\n")

    assert [s["title"] for s in sections] == ["Overview", "One", "Two"]
    assert sections[2]["content"] == "b"


def test_extract_sections_keeps_code_comments_inside_their_section():
    text = "# Ports\nList them:\n```bash\n# list listening sockets\nss -tlnp\n```\n"

    sections = ai_indexer.extract_sections(text)

    assert [s["title"] for s in sections] == ["Ports"]
    assert "# list listening sockets" in sections[0]["content"]
    assert sections[0]["content"].count("```") == 2


def test_score_record_ranks_title_over_body_matches():
    title_hit = ai_grounding.score_record("kerberoasting", RECORDS[0])
    no_hit = ai_grounding.score_record("kerberoasting", RECORDS[1])

    assert title_hit > 0
    assert no_hit == 0


def test_score_record_ignores_short_tokens():
    assert ai_grounding.score_record("ss", RECORDS[1]) == 0.0


def test_search_returns_best_match_first(tmp_path, monkeypatch):
    index = tmp_path / "index.jsonl"
    index.write_text("\n".join(json.dumps(r) for r in RECORDS), encoding="utf-8")
    monkeypatch.setattr(ai_grounding, "INDEX_FILE", index)

    results = ai_grounding.search("listening ports linux")

    assert results[0][0]["title"] == "Listening Ports"
    assert all(score > 0 for _, score in results)


def test_grounded_prompt_cites_source_paths(tmp_path, monkeypatch):
    index = tmp_path / "index.jsonl"
    index.write_text("\n".join(json.dumps(r) for r in RECORDS), encoding="utf-8")
    monkeypatch.setattr(ai_grounding, "INDEX_FILE", index)

    prompt = ai_grounding.build_grounded_prompt("kerberoasting hunt")

    assert "(tasks/kerberoasting-hunt.md)" in prompt


def test_query_ollama_returns_none_when_unreachable():
    # Port 9 (discard) on loopback is closed; the call must fail fast and quietly.
    assert ai_grounding.query_ollama("hello", host="http://127.0.0.1:9") is None
