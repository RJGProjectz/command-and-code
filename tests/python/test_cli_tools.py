"""Tests for the terminal tools: cc_cli, lookup and hunt_runner, plus an import smoke test for every tool.

security_domain: Code Quality
Author: RJGProjectz
Created: 2026-10-11T19:30:00Z
"""
import importlib

import pytest

from conftest import ROOT
from tools import cc_cli, hunt_runner, lookup


def test_cc_cli_search_ranks_title_match_first(docs_tree, monkeypatch):
    monkeypatch.setattr(cc_cli, "DOCS", docs_tree)

    results = cc_cli.search_pages("kerberoasting")

    assert [p["title"] for _, p in results] == ["Kerberoasting Hunt"]


def test_cc_cli_search_filters_by_platform(docs_tree, monkeypatch):
    monkeypatch.setattr(cc_cli, "DOCS", docs_tree)

    results = cc_cli.search_pages("", platform="linux")

    assert [p["title"] for _, p in results] == ["Listening Ports"]


def test_cc_cli_extract_code_blocks_skips_empty_fences():
    body = "```powershell\nGet-Process\n```\n```\n```\n```bash\nss -tlnp\n```\n"

    assert cc_cli.extract_code_blocks(body) == [("powershell", "Get-Process"), ("bash", "ss -tlnp")]


def test_lookup_search_filters_by_task(docs_tree, monkeypatch):
    monkeypatch.setattr(lookup, "DOCS", docs_tree)

    results = lookup.search_pages("", task="Threat Hunting")

    assert [p["title"] for p in results] == ["Kerberoasting Hunt"]


def test_hunt_runner_parses_front_matter_lists_and_scalars():
    content = "---\ntitle: Hunt\ntasks:\n  - Threat Hunting\n  - Incident Response\n---\nbody"

    assert hunt_runner.parse_frontmatter(content) == {
        "title": "Hunt",
        "tasks": ["Threat Hunting", "Incident Response"],
    }


def test_hunt_runner_without_front_matter_returns_empty():
    assert hunt_runner.parse_frontmatter("# just a heading") == {}


def test_hunt_runner_lists_code_block_languages():
    assert hunt_runner.extract_code_blocks("```kql\nx\n```\n```spl\ny\n```") == ["kql", "spl"]


# Not every tool parses arguments (some run their full job on any invocation), so only import them.
TOOLS = sorted(p.stem for p in (ROOT / "tools").glob("*.py"))


@pytest.mark.parametrize("module", TOOLS)
def test_tool_imports_without_side_effects(module):
    importlib.import_module(f"tools.{module}")
