# Contributing to Command & Code

## Principles

1. **Never invent.** Commands, registry paths, GPO paths, KQL fields, SPL syntax, S1QL syntax, API endpoints and configuration locations must come from vendor documentation or testing. If you cannot verify something, mark the page `verified: false` and say **VERIFY BEFORE PRODUCTION USE**.
2. **Answer "why".** For each useful command: what it does, why you would use it, important options, what the output tells you, security relevance, variations, related entries.
3. **One home per fact.** Put knowledge in one page and link to it. Workflows link to entries; they do not copy commands.
4. **Concise and operational.** A field manual, not an essay. Do not turn a one-line command into an article.
5. **Do not force equivalence or mappings.** Leave out a KQL/SPL/S1QL equivalent or an ATT&CK technique if it does not genuinely fit.

## Workflow

```bash
git switch -c add-linux-auditd-entry
cp templates/knowledge-entry.md docs/platforms/linux/auditd.md
# edit the page, add it to nav in mkdocs.yml
python tools/cc.py index
python tools/cc.py check
python tools/cc.py code
mkdocs build --strict
git add . && git commit -m "Add auditd entry"
git push -u origin add-linux-auditd-entry
```

Open a pull request. The **Build** workflow must pass before merging.

## Front matter

See [`docs/references/metadata.md`](docs/references/metadata.md). Platform, language and task values must exist in `tools/vocabulary.yml` — add new values there first, with the page they should link to.

## Writing guidance

- Headings are tasks phrased the way someone would search: *Find a process by PID*, not *Win32_Process*.
- Show PowerShell that runs on **Windows PowerShell 5.1** unless the entry says *PowerShell 7+*.
- Use realistic placeholders that still parse: `1234` for a PID, `203.0.113.10` / `198.51.100.7` for IPs (documentation ranges), `contoso.com` for domains, `jdoe` for users. Avoid `<angle-bracket>` placeholders inside PowerShell and Bash blocks — they break the syntax checker and the shell.
- Never use `$pid`, `$host`, `$input`, `$args`, `$error`, `$matches` or `$event` as variable names in PowerShell.
- Prefer `Get-CimInstance` over `Get-WmiObject` and `wmic`.
- Label code fences with the correct language (`powershell`, `bash`, `python`, `kql`, `spl`, `yaml`, `text`). S1QL uses `text` (no highlighter).
- Add **Sources** with official documentation links.

## Scripts

- Live in `scripts/<language>/`, start from the templates on the language automation pages, and are documented on the matching `docs/toolbox/` page.
- Read-only by default. Anything that changes state needs `SupportsShouldProcess` (`-WhatIf`) in PowerShell or an explicit flag in Bash/Python.
- No secrets in code, arguments or examples — read tokens from the environment or a secret store.
- PowerShell scripts must pass PSScriptAnalyzer at Warning level; Bash scripts must pass `shellcheck`. Keep scripts ASCII-only so Windows PowerShell 5.1 reads them correctly without a BOM.

## Importing existing work

When adding existing scripts, procedures or research, do not drop them into a miscellaneous folder:

1. Identify what it is.
2. Classify it: platform, language/technology, task.
3. Find related existing entries.
4. Extract reusable commands, queries and configuration into entries.
5. Put the implementation in `scripts/` and document it in `docs/toolbox/`.
6. Link it from the relevant workflows.
7. Record the reasoning and use case.
