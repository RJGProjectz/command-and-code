"""Fixture tests for scripts/bash/FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh (WP-59).

The monitor reads a synthetic audit.log (SELinux AVC, AppArmor, execve EACCES, fapolicyd FANOTIFY) and a
synthetic syslog file (fapolicyd deny_syslog line, kernel AppArmor line) from fixtures/cis_block_linux, so
no live host is read.

security_domain: Compliance / Detection
Author: RJGProjectz
Created: 2026-10-19T17:30:00Z
Last Modified: 2026-10-19T17:30:00Z
"""
import json
import subprocess
from pathlib import Path

import pytest

from tools import cc

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "bash" / "FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cis_block_linux"
BASH = cc.find_bash()

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")
MANDATORY = ("timestamp", "host", "tool", "version", "execution_id", "level", "action", "result")


def run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    cmd = [BASH, SCRIPT.as_posix(), "--log-dir", (tmp_path / "Logs").as_posix(), *args]
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=300)


def events(tmp_path: Path, *args: str) -> list[dict]:
    proc = run(tmp_path, "--audit-log", (FIXTURES / "audit.log").as_posix(),
               "--syslog", (FIXTURES / "messages").as_posix(), *args)
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def by_path(items: list[dict]) -> dict[str, dict]:
    return {item["path"]: item for item in items}


@pytest.fixture(scope="module")
def rhel_all(tmp_path_factory) -> list[dict]:
    return events(tmp_path_factory.mktemp("rhel"), "--profile", "rhel9", "--include-audit")


@pytest.fixture(scope="module")
def ubuntu_blocks(tmp_path_factory) -> list[dict]:
    return events(tmp_path_factory.mktemp("ubuntu"), "--profile", "ubuntu2404")


def test_event_schema(rhel_all):
    assert len(rhel_all) == 8
    for item in rhel_all:
        for key in MANDATORY:
            assert key in item, key
        assert item["tool"] == "FUNC_BASH_GET_CIS_BLOCK_EVENTS"
        assert item["action"] == "cis.block"
        assert item["environment"] == "Test"
        assert item["benchmark"] == "CIS Red Hat Enterprise Linux 9 v2.0.0"
        assert item["level"] == ("INFO" if item["result"] == "Audited" else "WARN")


def test_selinux_mapping(rhel_all):
    items = by_path(rhel_all)
    blocked = items["dropper"]
    assert (blocked["control"], blocked["result"], blocked["cis_id"]) == ("selinux", "Blocked", "1.3.1.5")
    assert "tclass=file" in blocked["detail"] and "{ execute }" in blocked["detail"]
    audited = items["/srv/www/secret.conf"]
    assert (audited["result"], audited["cis_id"]) == ("Audited", "1.3.1.4")


def test_noexec_pairs_syscall_and_path(rhel_all):
    items = by_path(rhel_all)
    miner = items["/dev/shm/miner"]
    assert (miner["control"], miner["user"], miner["process"]) == ("noexec", "1001", "bash")
    assert miner["cis_id"] == "1.1.2.2.4"
    # EACCES outside /tmp, /dev/shm, /var/tmp is a permission problem, not a noexec block.
    assert "/home/alice/notes.sh" not in items
    # A successful open of a file under /tmp is not an event.
    assert "/tmp/readme" not in items


def test_fapolicyd_audit_and_syslog(rhel_all):
    items = by_path(rhel_all)
    fan = items["/home/bob/tool.so"]
    assert (fan["control"], fan["process"], fan["user"], fan["cis_id"]) == ("fapolicyd", "/usr/bin/python3.9", "1002", "")
    syslog = items["/home/carol/unsigned"]
    assert syslog["control"] == "fapolicyd" and "dec=deny_syslog" in syslog["detail"]
    assert "/usr/bin/ls" not in items


def test_apparmor_from_audit_and_kernel_log(ubuntu_blocks):
    items = by_path(ubuntu_blocks)
    assert len(ubuntu_blocks) == 6
    assert all(item["result"] == "Blocked" for item in ubuntu_blocks)
    for path in ("/tmp/payload", "/home/dave/.ssh/id_ed25519"):
        assert items[path]["control"] == "apparmor"
        assert items[path]["cis_id"] == "1.3.1.3"
    assert "/etc/shadow" not in items  # complain mode (ALLOWED) only with --include-audit
    assert items["dropper"]["cis_id"] == ""  # SELinux IDs are cited for the rhel9 profile only


def test_whatif_reads_nothing(tmp_path):
    proc = run(tmp_path, "--whatif", "--audit-log", (FIXTURES / "audit.log").as_posix())
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert "[WHATIF]" in proc.stderr


def test_rejects_unknown_profile(tmp_path):
    proc = run(tmp_path, "--profile", "debian12")
    assert proc.returncode == 2
