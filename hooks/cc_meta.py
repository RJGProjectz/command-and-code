"""MkDocs hooks for Command & Code.

1. Metadata strip: reads each entry's front matter (platforms, languages, tasks,
   verified, last_verified, aliases) and inserts linked chips under the first H1.
   Chips link to the browse page for that value, as defined in tools/vocabulary.yml.
2. Script downloads: publishes scripts/ with the site and rewrites GitHub-relative
   links (../../scripts/...) to the published location.
3. Table pipes: removes the backslash GitHub requires before a pipe inside a code
   span in a table cell, which Python-Markdown would otherwise print.
4. Platform switcher: on docs/platforms/<platform>/<slug>.md, links the same slug on
   sibling platforms (Linux/Windows, Azure/AWS/GCP) so readers can jump across.

The Markdown files themselves are never modified, so they stay correct on GitHub.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

import yaml

_VOCAB_PATH = Path(__file__).resolve().parent.parent / "tools" / "vocabulary.yml"
_VOCAB: dict | None = None


def _vocab() -> dict:
    global _VOCAB
    if _VOCAB is None:
        with _VOCAB_PATH.open(encoding="utf-8") as handle:
            _VOCAB = yaml.safe_load(handle)
    return _VOCAB


def _chip(label: str, target: str | None, page_src: str, css: str) -> str:
    if not target or target == page_src:
        return f'<span class="cc-chip {css}">{label}</span>'
    rel = posixpath.relpath(target, posixpath.dirname(page_src) or ".")
    return f"[{label}]({rel}){{ .cc-chip .{css} }}"


_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"


def on_files(files, config):  # noqa: D103 - MkDocs hook signature
    """Publish scripts/ alongside the site so documentation can link to downloads.

    Source Markdown links to scripts with the path that works on GitHub
    (e.g. ../../scripts/powershell/X.ps1 from docs/toolbox/). on_page_markdown
    rewrites those links to the published location.
    """
    from mkdocs.structure.files import File

    for path in sorted(_SCRIPTS.rglob("*")):
        if path.is_file():
            rel = path.relative_to(_ROOT).as_posix()
            files.append(File(rel, str(_ROOT), config["site_dir"], config["use_directory_urls"]))
    return files


def _rewrite_script_links(markdown: str, src_uri: str) -> str:
    depth = src_uri.count("/")
    github_prefix = "../" * (depth + 1) + "scripts/"
    site_prefix = "../" * depth + "scripts/"
    return markdown.replace("](" + github_prefix, "](" + site_prefix)


_CODE_SPAN = re.compile(r"`[^`\n]*`")
_TABLE_ROW = re.compile(r"^\s*\|")


def _unescape_table_pipes(markdown: str) -> str:
    """GitHub needs `\\|` for a pipe inside a code span in a table cell; Python-Markdown
    already protects code spans and would print the backslash. Strip it for the site."""
    lines = markdown.split("\n")
    for i, line in enumerate(lines):
        if _TABLE_ROW.match(line) and "\\|" in line:
            lines[i] = _CODE_SPAN.sub(lambda m: m.group(0).replace("\\|", "|"), line)
    return "\n".join(lines)


# Sibling platforms whose pages share slugs; the order is the order shown.
_SWITCH_GROUPS = (
    (("linux", "Linux"), ("windows", "Windows")),
    (("azure", "Azure"), ("aws", "AWS"), ("gcp", "Google Cloud")),
)


def _switcher(src_uri: str, docs_dir: str) -> str:
    parts = src_uri.split("/")
    if len(parts) != 3 or parts[0] != "platforms":
        return ""
    _, platform, name = parts
    for group in _SWITCH_GROUPS:
        if platform not in dict(group):
            continue
        items = []
        for other, label in group:
            if other == platform:
                items.append(f'<span class="cc-switch-item cc-current">{label}</span>')
            elif (Path(docs_dir) / "platforms" / other / name).is_file():
                items.append(f"[{label}](../{other}/{name}){{ .cc-switch-item }}")
        if len(items) < 2:
            return ""
        return '<span class="cc-switch-label">Same topic on</span> ' + " ".join(items) + "\n{ .cc-switch }\n"
    return ""


def _insert_after_h1(markdown: str, block: str) -> str:
    lines = markdown.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith("# "):
            lines.insert(index + 1, "\n" + block + "\n")
            return "".join(lines)
    return block + "\n" + markdown


def on_page_markdown(markdown, page, config, files):  # noqa: D103 - MkDocs hook signature
    markdown = _rewrite_script_links(markdown, page.file.src_uri)
    markdown = _unescape_table_pipes(markdown)
    switch = _switcher(page.file.src_uri, config["docs_dir"])
    if switch:
        markdown = _insert_after_h1(markdown, switch)
    meta = page.meta or {}
    if meta.get("type", "entry") == "index":
        return markdown

    vocab = _vocab()
    src = page.file.src_uri
    chips: list[str] = []
    for key, css in (("platforms", "cc-platform"), ("languages", "cc-language"), ("tasks", "cc-task")):
        for value in meta.get(key) or []:
            chips.append(_chip(str(value), vocab.get(key, {}).get(value), src, css))

    if "verified" in meta:
        if meta.get("verified") is True:
            when = meta.get("last_verified")
            label = f"Verified {when}" if when else "Verified"
            chips.append(f'<span class="cc-chip cc-verified">{label}</span>')
        else:
            chips.append('<span class="cc-chip cc-unverified">Unverified</span>')

    if not chips:
        return markdown

    strip = " ".join(chips) + "\n{ .cc-meta }\n"
    aliases = meta.get("aliases") or []
    if aliases:
        # Rendered as visible text so the search index picks up alternative phrasings.
        strip += "\nAlso searched as: " + " · ".join(str(a) for a in aliases) + "\n{ .cc-aliases }\n"
    return _insert_after_h1(markdown, strip)
