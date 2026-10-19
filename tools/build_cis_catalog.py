#!/usr/bin/env python3
"""Build a CIS check catalog (JSON) from Tenable Windows .audit files.

Script Name : build_cis_catalog.py
Purpose     : Turn the machine-readable checks in Tenable's CIS audit files into the data-driven
              catalog that scripts/powershell/Invoke-CisWindowsAudit.ps1 evaluates. Keeps the
              audit engine free of hard-coded settings: a new benchmark release is a re-run.
Inputs      : One or more .audit files (e.g. CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1.audit and
              ..._L2.audit, downloaded by the operator from tenable.com/audits). The level of every
              check is taken from the file name (_L1 / _L2); Windows Server files also name the
              profile (_L1_MS / _L2_DC), one catalog per profile.
Outputs     : JSON catalog: benchmark, version, source files + sha256, and one entry per CIS
              recommendation with id, title, level, section and structured tests.
Security    : Security Domain: Compliance / Hardening. Only recommendation IDs, titles and the
              setting each one checks are written; CIS rationale/remediation text and Tenable
              file contents are not copied. The .audit files themselves are never committed.
Author      : RJGProjectz
Version     : 1.1.0
Created     : 2026-10-16T14:30:00Z
Last Modified: 2026-10-19T03:25:00Z
KB Article  : docs/tasks/hardening/windows-11-cis-audit-tool.md
Source Repo : https://www.tenable.com/audits (audit file format: Tenable Compliance Checks Reference)

Example:
    python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows 11 Enterprise" \
        --version 5.1.0 --out scripts/cis/catalogs/windows11-enterprise-v5.1.0.json L1.audit L2.audit
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

ID_TITLE = re.compile(r"^(\d+(?:\.\d+)*)\s+(.*)$")
FIELD = re.compile(r'^\s*(\w+)\s*:\s*(.*?)\s*$')
VARIABLE = re.compile(r"<name>(\w+)</name>\s*#\s*<default>(.*?)</default>", re.S)

# Tenable policy names -> secedit [System Access] keys.
SECEDIT_KEYS = {
    "ENFORCE_PASSWORD_HISTORY": "PasswordHistorySize",
    "MAXIMUM_PASSWORD_AGE": "MaximumPasswordAge",
    "MINIMUM_PASSWORD_AGE": "MinimumPasswordAge",
    "MINIMUM_PASSWORD_LENGTH": "MinimumPasswordLength",
    "COMPLEXITY_REQUIREMENTS": "PasswordComplexity",
    "REVERSIBLE_ENCRYPTION": "ClearTextPassword",
    "FORCE_LOGOFF": "ForceLogoffWhenHourExpire",
    "LOCKOUT_DURATION": "LockoutDuration",
    "LOCKOUT_THRESHOLD": "LockoutBadCount",
    "LOCKOUT_RESET": "ResetLockoutCount",
    "LOCKOUT_ADMINS": "AllowAdministratorLockout",
}
ACCOUNT_KEYS = {
    ("GUEST_ACCOUNT", "POLICY_SET"): "EnableGuestAccount",
    ("GUEST_ACCOUNT", "POLICY_TEXT"): "NewGuestName",
    ("ADMINISTRATOR_ACCOUNT", "POLICY_SET"): "EnableAdminAccount",
    ("ADMINISTRATOR_ACCOUNT", "POLICY_TEXT"): "NewAdministratorName",
}


# --------------------------------------------------------------------------- audit file tree
def tokenize_tree(text: str) -> list:
    """Parse the nested <if>/<condition>/<then>/<else>/<custom_item>/<report> structure."""
    tag = re.compile(r"<(/?)(check_type|group_policy|if|condition|then|else|custom_item|report)([^>]*)>")
    root: list = []
    stack = [("root", {}, root)]
    pos = 0
    for m in tag.finditer(text):
        closing, name, attrs = m.group(1), m.group(2), m.group(3)
        if name in ("custom_item", "report"):
            if not closing:
                pos = m.end()
                stack.append((name, {"attrs": attrs}, []))
            else:
                kind, meta, _ = stack.pop()
                meta["body"] = text[pos:m.start()]
                stack[-1][2].append((kind, meta, []))
            continue
        if not closing:
            node = (name, {"attrs": attrs}, [])
            stack[-1][2].append(node)
            stack.append(node)
        else:
            stack.pop()
    return root


def fields(body: str) -> dict:
    """Single-line fields of an item (multi-line text fields such as info are skipped)."""
    out = {}
    for line in body.splitlines():
        m = FIELD.match(line)
        if m and m.group(1) not in out:
            out[m.group(1)] = m.group(2)
    return out


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


# --------------------------------------------------------------------------- value expressions
def lex(expr: str) -> list:
    tokens, i = [], 0
    while i < len(expr):
        c = expr[i]
        if c.isspace():
            i += 1
        elif expr.startswith("&&", i) or expr.startswith("||", i):
            tokens.append(expr[i:i + 2]); i += 2
        elif c in "()":
            tokens.append(c); i += 1
        elif c == '"':
            j = expr.index('"', i + 1)
            tokens.append(("lit", expr[i + 1:j])); i = j + 1
        else:
            j = i
            while j < len(expr) and not expr[j].isspace() and expr[j] not in "()" and not expr.startswith(("&&", "||"), j):
                j += 1
            tokens.append(("lit", expr[i:j])); i = j
    return tokens


def parse_expr(expr: str):
    """Tree of ('or'|'and', [children]) and ('lit', text)."""
    tokens = lex(expr)
    pos = 0

    def parse_or():
        nonlocal pos
        items = [parse_and()]
        while pos < len(tokens) and tokens[pos] == "||":
            pos += 1
            items.append(parse_and())
        return items[0] if len(items) == 1 else ("or", items)

    def parse_and():
        nonlocal pos
        items = [parse_atom()]
        while pos < len(tokens) and tokens[pos] == "&&":
            pos += 1
            items.append(parse_atom())
        return items[0] if len(items) == 1 else ("and", items)

    def parse_atom():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        if tok == "(":
            node = parse_or()
            pos += 1  # ')'
            return node
        return tok

    if not tokens:
        return ("lit", "")
    return parse_or()


def to_sets(node) -> list[list[str]]:
    """Expand an and/or tree into alternative sets of names (disjunctive normal form)."""
    if node[0] == "lit":
        return [[node[1]]] if node[1] != "" else [[]]
    if node[0] == "or":
        return [s for child in node[1] for s in to_sets(child)]
    result = [[]]
    for child in node[1]:
        result = [a + b for a in result for b in to_sets(child)]
    return result


def scalar(text: str, variables: dict, value_type: str, check_type: str | None) -> dict:
    """One literal -> expectation object."""
    m = re.fullmatch(r"@(\w+)@", text)
    if m:
        text = variables.get(m.group(1), text)
    if check_type == "CHECK_REGEX":
        return {"op": "regex", "pattern": text}
    if check_type == "CHECK_NOT_REGEX":
        return {"op": "notRegex", "pattern": text}
    if check_type == "CHECK_NOT_EQUAL":
        return {"op": "ne", "value": text}
    m = re.fullmatch(r"\[(MIN|-?\d+)\.\.(MAX|-?\d+)\]", text)
    if m:
        return {"op": "range",
                "min": None if m.group(1) == "MIN" else int(m.group(1)),
                "max": None if m.group(2) == "MAX" else int(m.group(2))}
    if value_type == "POLICY_SET":
        text = {"Enabled": "1", "Disabled": "0"}.get(text, text)
    return {"op": "eq", "value": text}


def expectation(f: dict, variables: dict) -> dict:
    value_type = f.get("value_type", "")
    check_type = f.get("check_type")
    raw = f.get("value_data", '""')
    tree = parse_expr(raw)
    if value_type in ("USER_RIGHT", "POLICY_MULTI_TEXT"):
        mode = "superset" if check_type == "CHECK_SUPERSET" else "exact"
        return {"op": "set", "mode": mode, "anyOf": to_sets(tree)}
    if value_type == "AUDIT_SET":
        return {"op": "in", "values": [s[0] for s in to_sets(tree)]}

    def walk(node):
        if node[0] == "lit":
            return scalar(node[1], variables, value_type, check_type)
        return {"op": "any" if node[0] == "or" else "all", "of": [walk(c) for c in node[1]]}

    return walk(tree)


# --------------------------------------------------------------------------- items -> tests
def make_test(f: dict, variables: dict) -> dict | None:
    kind = f.get("type")
    expect = expectation(f, variables)
    if kind == "REGISTRY_SETTING" or kind == "BANNER_CHECK":
        test = {"source": "Registry", "key": unquote(f["reg_key"]), "name": unquote(f["reg_item"]),
                "valueType": f.get("value_type"), "expect": expect}
        if kind == "BANNER_CHECK":
            test["expect"] = {"op": "notEmpty"}
        opt = f.get("reg_option")
        if opt == "CAN_BE_NULL":
            test["allowMissing"] = True
        elif opt == "MUST_NOT_EXIST":
            test["mustNotExist"] = True
        return test
    if kind == "REG_CHECK":
        return {"source": "Registry", "key": unquote(f["value_data"]), "name": unquote(f["key_item"]),
                "mustNotExist": f.get("reg_option") == "MUST_NOT_EXIST", "expect": {"op": "absent"}}
    if kind in ("PASSWORD_POLICY", "LOCKOUT_POLICY"):
        policy = f.get("password_policy") or f.get("lockout_policy")
        return {"source": "SecurityPolicy", "key": SECEDIT_KEYS[policy], "expect": expect}
    if kind == "CHECK_ACCOUNT":
        return {"source": "SecurityPolicy", "key": ACCOUNT_KEYS[(f["account_type"], f["value_type"])],
                "expect": expect}
    if kind == "ANONYMOUS_SID_SETTING":
        return {"source": "SecurityPolicy", "key": "LSAAnonymousNameLookup", "expect": expect}
    if kind == "USER_RIGHTS_POLICY":
        return {"source": "UserRight", "right": f["right_type"], "expect": expect}
    if kind == "AUDIT_POLICY_SUBCATEGORY":
        return {"source": "AuditPolicy", "subcategory": unquote(f["audit_policy_subcategory"]), "expect": expect}
    if kind == "AUDIT_POWERSHELL" and "Spooler" in f.get("powershell_args", ""):
        return {"source": "Service", "name": "Spooler", "property": "Status", "expect": expect}
    return None


def split_title(description: str):
    m = ID_TITLE.match(unquote(description))
    return (m.group(1), m.group(2)) if m else (None, None)


def collect(nodes: list, level: str, variables: dict, out: dict, problems: list) -> None:
    for kind, meta, children in nodes:
        if kind == "custom_item":
            f = fields(meta["body"])
            cid, title = split_title(f.get("description", ""))
            if not cid:
                continue  # helper/platform items without a CIS number
            test = make_test(f, variables)
            if test is None:
                problems.append(f"{cid}: unsupported item type {f.get('type')}")
                continue
            add(out, cid, title, level, [test])
        elif kind == "if":
            handle_if(children, level, variables, out, problems)
        else:
            collect(children, level, variables, out, problems)


def handle_if(children: list, level: str, variables: dict, out: dict, problems: list) -> None:
    parts = {k: c for k, _, c in children}
    cond_meta = next(m for k, m, _ in children if k == "condition")
    cond_items = [fields(m["body"]) for k, m, _ in parts.get("condition", []) if k == "custom_item"]
    then = parts.get("then", [])
    reports = [fields(m["body"]) for k, m, _ in then if k == "report"]
    numbered = [r for r in reports if split_title(r.get("description", ""))[0]]
    if numbered and 'auto:"FAILED"' in cond_meta["attrs"]:
        # Composite recommendation: every condition item must pass.
        cid, title = split_title(numbered[0]["description"])
        tests = [make_test(f, variables) for f in cond_items]
        if None in tests:
            problems.append(f"{cid}: unsupported condition item")
            return
        add(out, cid, title, level, tests)
        return
    if numbered or not cond_items:
        return
    when = [make_test(f, variables) for f in cond_items]
    if not any(t and t["source"] == "Service" for t in when):
        # Platform guard ("Windows 11 is installed"): record it once and audit its body.
        if "applicability" not in out:
            out["applicability"] = [t for t in when if t]
        collect(then, level, variables, out, problems)
        return
    # Variant recommendation (e.g. depends on Print Spooler state): then-branch applies when the
    # condition holds, else-branch otherwise.
    for branch, apply_when in (("then", when), ("else", None)):
        for k, m, _ in parts.get(branch, []):
            if k != "custom_item":
                continue
            f = fields(m["body"])
            cid, title = split_title(f.get("description", ""))
            if not cid:
                continue
            test = make_test(f, variables)
            entry = out.setdefault(cid, {"id": cid, "title": title, "level": level,
                                         "section": section_of(cid), "variants": []})
            entry.setdefault("variants", []).append({"when": apply_when, "tests": [test]})


def section_of(cid: str) -> str:
    return cid.split(".")[0]


def add(out: dict, cid: str, title: str, level: str, tests: list) -> None:
    if cid in out:
        out[cid]["tests"].extend(tests)
    else:
        out[cid] = {"id": cid, "title": title, "level": level, "section": section_of(cid), "tests": tests}


def sort_key(cid: str):
    return [int(p) for p in cid.split(".")]


# Server audit files carry the profile after the level: _L1_MS / _L2_DC (current Tenable names) or
# _L1_Member_Server / _L1_Domain_Controller (older releases). Client files have no profile.
LEVEL_PROFILE = re.compile(r"_(L\d)(?:_(MS|DC|Member_Server|Domain_Controller))?(?:_BL)?\.audit$", re.I)
PROFILE_NAMES = {"ms": "MS", "member_server": "MS", "dc": "DC", "domain_controller": "DC"}


def level_and_profile(name: str) -> tuple[str, str | None]:
    """Level (L1/L2) and server profile (MS/DC, None for client benchmarks) from an audit file name."""
    m = LEVEL_PROFILE.search(name)
    if m:
        role = PROFILE_NAMES[m.group(2).lower()] if m.group(2) else None
        return m.group(1).upper(), role
    m = re.search(r"(L\d)", Path(name).stem)
    return (m.group(1) if m else "L1"), None


def build(paths: list[Path], benchmark: str, version: str) -> tuple[dict, list]:
    checks: dict = {}
    sources, problems = [], []
    applicability: list = []
    profiles: set = set()
    for path in paths:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        level, role = level_and_profile(path.name)
        profiles.add(role)
        variables = {k: v.strip() for k, v in VARIABLE.findall(text)}
        collect(tokenize_tree(text), level, variables, checks, problems)
        if "applicability" in checks:
            applicability = checks.pop("applicability")
        sources.append({"file": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "level": level,
                        "profile": role})
    if len(profiles) > 1:
        raise ValueError("audit files mix server profiles (MS and DC, or client and server): "
                         "build one catalog per profile")
    catalog = {
        "schema": "cc.cis.catalog/1",
        "benchmark": benchmark,
        "version": version,
        "profile": next(iter(profiles), None),
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "tools/build_cis_catalog.py",
        "sources": sources,
        "notice": "Recommendation IDs and titles are from the CIS Benchmark; the benchmark text is licensed by "
                  "CIS and is not reproduced. Check logic derived from Tenable audit files.",
        "applicability": applicability,
        "checks": [checks[k] for k in sorted(checks, key=sort_key)],
    }
    return catalog, problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("audit", nargs="+", type=Path, help=".audit files (_L1 / _L2 in the name; server: _L1_MS / _L1_DC)")
    ap.add_argument("--benchmark", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        catalog, problems = build(args.audit, args.benchmark, args.version)
    except ValueError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"WARN {p}", file=sys.stderr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(catalog, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    levels = {}
    for c in catalog["checks"]:
        levels[c["level"]] = levels.get(c["level"], 0) + 1
    role = f" profile {catalog['profile']}" if catalog["profile"] else ""
    print(f"wrote {args.out}: {len(catalog['checks'])} checks {levels}{role}, {len(problems)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
