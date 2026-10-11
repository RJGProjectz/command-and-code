"""Shared pytest setup: make `tools.*` importable from the repository root.

security_domain: Code Quality
Author: RJGProjectz
Created: 2026-10-11T19:30:00Z
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def docs_tree(tmp_path):
    """A tiny docs/ tree with front matter, used by the search tools."""
    docs = tmp_path / "docs"
    (docs / "tasks").mkdir(parents=True)
    (docs / "platforms").mkdir()
    (docs / "tasks" / "kerberoasting-hunt.md").write_text(
        "---\n"
        "title: Kerberoasting Hunt\n"
        "type: workflow\n"
        "platforms: [Windows]\n"
        "languages: [PowerShell]\n"
        "tasks: [Threat Hunting]\n"
        "tags: [kerberos, spn]\n"
        "---\n"
        "# Kerberoasting Hunt\n\nLook for RC4 service tickets.\n\n"
        "```powershell\nGet-WinEvent -FilterHashtable @{LogName='Security'; Id=4769}\n```\n",
        encoding="utf-8",
    )
    (docs / "platforms" / "linux-ports.md").write_text(
        "---\n"
        "title: Listening Ports\n"
        "platforms: [Linux]\n"
        "languages: [Bash]\n"
        "tasks: [Incident Response]\n"
        "---\n"
        "# Listening Ports\n\n```bash\n# list listening sockets\nss -tlnp\n```\n",
        encoding="utf-8",
    )
    return docs
