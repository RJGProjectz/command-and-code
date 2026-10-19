"""Fixture tests for scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh (WP-68).

The script runs with --root against a synthetic file tree (tests/python/fixtures/service_account_linux),
so no live host is read. Credential-store files are created per test because git cannot keep 0600 modes.

security_domain: Identity
Author: RJGProjectz
Created: 2026-10-18T23:00:00Z
Last Modified: 2026-10-18T23:00:00Z
"""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tools import cc

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "bash" / "FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "service_account_linux"
BASH = cc.find_bash()

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")
MANDATORY = ("timestamp", "host", "tool", "version", "execution_id")


def run_audit(root, *extra):
    log_dir = Path(root).parent / "logs"
    completed = subprocess.run(
        [BASH, SCRIPT.as_posix(), "--root", Path(root).as_posix(), "--log-dir", log_dir.as_posix(), *extra],
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    findings = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    return findings, log_dir


def by_check(findings, check):
    return [f for f in findings if f["check"] == check]


@pytest.fixture(scope="module")
def audit(tmp_path_factory):
    work = tmp_path_factory.mktemp("sa")
    tree = work / "root"
    shutil.copytree(FIXTURE, tree)
    plain = tree / "etc" / "credstore"
    encrypted = tree / "etc" / "credstore.encrypted"
    plain.mkdir()
    encrypted.mkdir()
    (plain / "db-password").write_text("fixture-not-a-secret\n")
    (plain / "api-token").write_text("fixture-not-a-secret\n")
    (encrypted / "db-password.cred").write_text("fixture-not-a-secret\n")
    os.chmod(plain / "db-password", 0o644)
    os.chmod(plain / "api-token", 0o600)
    os.chmod(encrypted / "db-password.cred", 0o644)
    findings, log_dir = run_audit(tree)
    return findings, log_dir, tree


def test_every_line_is_ndjson_with_the_mandatory_fields(audit):
    findings, _, _ = audit
    assert findings
    for finding in findings:
        for field in MANDATORY:
            assert finding[field], field
        assert finding["tool"] == "FUNC_BASH_AUDIT_SERVICE_ACCOUNT"
        assert finding["action"] == "audit"
        assert finding["timestamp"].endswith("Z")
    assert len({f["execution_id"] for f in findings}) == 1
    assert {f["host"] for f in findings} == {"lnx01"}


def test_uid0_duplicate_and_empty_password(audit):
    findings, _, _ = audit
    assert [f["account"] for f in by_check(findings, "SA-UID0-DUPLICATE")] == ["backdoor"]
    assert [f["account"] for f in by_check(findings, "SA-EMPTY-PASSWORD")] == ["backdoor"]


def test_system_accounts_with_shell_skip_nologin_and_sync(audit):
    findings, _, _ = audit
    assert sorted(f["account"] for f in by_check(findings, "SA-SYSTEM-SHELL")) == ["legacysvc", "postgres"]


def test_system_accounts_with_usable_password(audit):
    findings, _, _ = audit
    hits = {f["account"]: f["severity"] for f in by_check(findings, "SA-SYSTEM-PASSWORD")}
    assert hits == {"legacysvc": "high", "postgres": "high"}


def test_sudo_nopasswd_and_all_grants(audit):
    findings, _, _ = audit
    nopasswd = {f["account"]: f["severity"] for f in by_check(findings, "SA-SUDO-NOPASSWD")}
    assert nopasswd == {"Defaults:deploy": "medium", "%appops": "medium", "legacysvc": "high"}
    sudo_all = {f["account"]: f["severity"] for f in by_check(findings, "SA-SUDO-ALL")}
    assert sudo_all == {"%sudo": "low", "bob": "medium"}


def test_sudoers_d_skips_files_with_dot_or_tilde(audit):
    findings, _, _ = audit
    accounts = {f["account"] for f in findings}
    assert "eve" not in accounts and "mallory" not in accounts


def test_continued_sudo_line_reports_its_first_line(audit):
    findings, _, _ = audit
    legacy = [f for f in by_check(findings, "SA-SUDO-NOPASSWD") if f["account"] == "legacysvc"][0]
    assert legacy["target"] == "/etc/sudoers.d/legacy:1"
    assert legacy["details"]["grants_all"] == "true"


def test_systemd_units_by_user_with_drop_ins(audit):
    findings, _, _ = audit
    users = {f["target"]: f["account"] for f in by_check(findings, "SA-UNIT-USER")}
    assert users == {"postgresql.service": "postgres", "app.service": "appsvc", "dyn.service": "dynamic"}
    roots = {f["target"]: f["severity"] for f in by_check(findings, "SA-UNIT-ROOT")}
    assert roots == {"sshd.service": "info", "backup.service": "low"}
    shell = by_check(findings, "SA-UNIT-USER-SHELL")
    assert [(f["target"], f["account"]) for f in shell] == [("postgresql.service", "postgres")]


@pytest.mark.skipif(sys.platform == "win32", reason="NTFS under Git Bash does not report POSIX modes")
def test_world_readable_credstore_files(audit):
    findings, _, _ = audit
    hits = {f["details"]["file"]: f["severity"] for f in by_check(findings, "SA-CREDSTORE-READABLE")}
    assert hits == {
        "/etc/credstore/db-password": "high",
        "/etc/credstore.encrypted/db-password.cred": "medium",
    }


def test_run_log_is_written_to_the_log_dir(audit):
    _, log_dir, _ = audit
    events = [json.loads(line) for line in (log_dir / "FUNC_BASH_AUDIT_SERVICE_ACCOUNT.ndjson").read_text().splitlines()]
    assert events and all(e["action"] == "log" for e in events)
    assert all(all(e[field] for field in MANDATORY) for e in events)


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX modes and a non-root user")
def test_unreadable_shadow_is_needs_review(tmp_path):
    tree = tmp_path / "root"
    shutil.copytree(FIXTURE, tree)
    os.chmod(tree / "etc" / "shadow", 0)
    findings, _ = run_audit(tree)
    review = by_check(findings, "SA-COLLECTION")
    assert [f["target"] for f in review] == ["/etc/shadow"]
    assert review[0]["result"] == "NeedsReview"
    assert not by_check(findings, "SA-SYSTEM-PASSWORD")


def test_uid_min_override(tmp_path):
    tree = tmp_path / "root"
    shutil.copytree(FIXTURE, tree)
    findings, _ = run_audit(tree, "--uid-min", "100")
    # postgres (UID 110) is now a regular user; legacysvc (997) is too.
    assert not by_check(findings, "SA-SYSTEM-SHELL")


def test_whatif_reads_nothing(tmp_path):
    tree = tmp_path / "root"
    shutil.copytree(FIXTURE, tree)
    findings, _ = run_audit(tree, "--whatif")
    assert findings == []


def test_prod_with_force_does_not_prompt(tmp_path):
    tree = tmp_path / "root"
    shutil.copytree(FIXTURE, tree)
    findings, _ = run_audit(tree, "--env", "Prod", "--force")
    assert findings and {f["environment"] for f in findings} == {"Prod"}


def test_rejects_bad_env(tmp_path):
    completed = subprocess.run(
        [BASH, SCRIPT.as_posix(), "--env", "Live", "--log-dir", (tmp_path / "logs").as_posix()],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""


def test_fixture_modes_are_not_needed_for_git():
    # Guard: the fixture must not depend on file modes git cannot store (credstore files are made in the test).
    assert not (FIXTURE / "etc" / "credstore").exists()
    assert stat.S_ISREG((FIXTURE / "etc" / "shadow").stat().st_mode)
