"""Tests for tools/cc.py: front-matter loading, page validation and code-block extraction.

security_domain: Code Quality
Author: RJGProjectz
Created: 2026-10-11T19:30:00Z
"""
import datetime as dt

from tools import cc


def make_page(rel, meta, body="# Title\n"):
    return cc.Page(path=cc.DOCS / rel, meta=meta, body=body)


def valid_meta(**overrides):
    meta = {
        "title": "Valid Entry",
        "tasks": ["Incident Response"],
        "platforms": ["Windows"],
        "verified": True,
        "last_verified": dt.date(2026, 10, 1),
    }
    meta.update(overrides)
    return meta


def test_load_page_parses_front_matter_and_body(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("---\ntitle: Hello\ntype: entry\n---\n# Hello\nbody\n", encoding="utf-8")

    page = cc.load_page(p)

    assert page.error is None
    assert page.meta == {"title": "Hello", "type": "entry"}
    assert page.body == "# Hello\nbody\n"


def test_load_page_reports_unclosed_front_matter(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("---\ntitle: Hello\n# no closing fence\n", encoding="utf-8")

    assert cc.load_page(p).error == "front matter is not closed with ---"


def test_load_page_reports_malformed_yaml(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("---\ntitle: [unclosed\n---\n# x\n", encoding="utf-8")

    assert cc.load_page(p).error.startswith("malformed YAML")


def test_valid_page_has_no_problems():
    assert cc.validate([make_page("tasks/a.md", valid_meta())]) == []


def test_unknown_vocabulary_term_is_reported():
    problems = cc.validate([make_page("tasks/a.md", valid_meta(platforms=["Windoze"]))])

    assert any("'Windoze' is not a known platform" in p for p in problems)


def test_missing_required_fields_are_reported():
    meta = valid_meta()
    del meta["tasks"]
    problems = cc.validate([make_page("tasks/a.md", meta)])

    assert any("missing required 'tasks'" in p for p in problems)


def test_unverified_page_must_carry_the_banner():
    meta = valid_meta(verified=False)
    without = cc.validate([make_page("tasks/a.md", meta)])
    with_banner = cc.validate([make_page("tasks/a.md", meta, f"# Title\n{cc.VERIFY_BANNER}\n")])

    assert any(cc.VERIFY_BANNER in p for p in without)
    assert with_banner == []


def test_verified_page_needs_last_verified_date():
    meta = valid_meta()
    del meta["last_verified"]

    assert any("last_verified" in p for p in cc.validate([make_page("tasks/a.md", meta)]))


def test_duplicate_titles_are_reported():
    problems = cc.validate([make_page("tasks/a.md", valid_meta()), make_page("tasks/b.md", valid_meta())])

    assert any("duplicate title" in p for p in problems)


def test_index_pages_skip_content_rules():
    assert cc.validate([make_page("tasks/index.md", {"title": "Tasks"})]) == []


def test_code_blocks_yield_language_code_and_line():
    text = "intro\n\n```powershell\nGet-Process\n```\n\n  ```bash\n  echo hi\n  ```\n"

    blocks = list(cc._code_blocks(text))

    assert blocks == [("powershell", "Get-Process", 3), ("bash", "echo hi", 7)]


def test_all_pages_skips_dot_directories(tmp_path, monkeypatch):
    # docs/ may be opened as an Obsidian vault: .obsidian/ and .trash/ are not site pages.
    (tmp_path / "a.md").write_text("# A\n", encoding="utf-8")
    for hidden in (".obsidian", ".trash"):
        (tmp_path / hidden).mkdir()
        (tmp_path / hidden / "x.md").write_text("no heading\n", encoding="utf-8")
    monkeypatch.setattr(cc, "DOCS", tmp_path)
    assert [p.rel for p in cc.all_pages()] == ["a.md"]


def _no_git_bash(monkeypatch, tmp_path, which_bash):
    monkeypatch.setattr(cc.sys, "platform", "win32")
    monkeypatch.setattr(cc.shutil, "which", lambda name: which_bash if name == "bash" else None)
    for env in ("ProgramFiles", "ProgramW6432", "LOCALAPPDATA"):
        monkeypatch.setenv(env, str(tmp_path / "empty"))


def test_find_bash_rejects_the_wsl_stub_on_windows(monkeypatch, tmp_path):
    _no_git_bash(monkeypatch, tmp_path, r"C:\Windows\System32\bash.exe")
    assert cc.find_bash() is None


def test_find_bash_prefers_git_bash_on_windows(monkeypatch, tmp_path):
    _no_git_bash(monkeypatch, tmp_path, r"C:\Windows\System32\bash.exe")
    git_bash = tmp_path / "pf" / "Git" / "bin" / "bash.exe"
    git_bash.parent.mkdir(parents=True)
    git_bash.write_bytes(b"")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "pf"))
    assert cc.find_bash() == str(git_bash)
