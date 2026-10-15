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
- Use realistic placeholders that still parse: `1234` for a PID, `<TARGET_IP>` / `<SECONDARY_IP>` for IPs (documentation ranges), `<DOMAIN>` for domains, `<USER>` for users. Avoid `<angle-bracket>` placeholders inside PowerShell and Bash blocks — they break the syntax checker and the shell.
- Never use `$pid`, `$host`, `$input`, `$args`, `$error`, `$matches` or `$event` as variable names in PowerShell.
- Prefer `Get-CimInstance` over `Get-WmiObject` and `wmic`.
- Label code fences with the correct language (`powershell`, `bash`, `python`, `kql`, `spl`, `yaml`, `text`). S1QL uses `text` (no highlighter).
- Add **Sources** with official documentation links.

## Editing in Obsidian (optional)

You can open `docs/` as an [Obsidian](https://obsidian.md/) vault to write and browse pages with its editor, search and graph. Obsidian is only an editor here: the site is still built by MkDocs and published to GitHub Pages, and nothing Obsidian-specific may end up in a page.

**Open the vault.** In Obsidian choose *Open folder as vault* and pick `docs/` (not the repository root, so `scripts/`, `site/` and the ledgers stay out of the vault). Obsidian creates its settings folder `docs/.obsidian/`; it is gitignored, and MkDocs skips it because `exclude_docs` always excludes dot-files and dot-directories.

**Set these once** (Settings):

| Setting | Value | Why |
| :--- | :--- | :--- |
| Files and links → Use [[Wikilinks]] | Off | MkDocs does not understand `[[wikilinks]]`; with this off Obsidian writes `[text](page.md)` links |
| Files and links → New link format | Relative path to file | Pages link with relative paths such as `../../platforms/windows/registry.md`; the other two formats produce links MkDocs cannot resolve |
| Files and links → Automatically update internal links | On | Renaming a page in Obsidian rewrites the links that point to it |
| Files and links → Default location for new attachments | In the folder specified below: `assets` | Keeps images next to `favicon.svg` and `social-card.png` instead of beside each page |
| Files and links → Deleted files | Move to system trash | Avoids a `docs/.trash/` folder (it is gitignored anyway) |
| Editor → Strict line breaks | On | Matches Markdown and MkDocs: a single newline does not break a line |
| Editor → Properties in document | Source | Shows front matter as raw YAML, so the Properties editor does not reformat lists or values that `tools/cc.py check` validates |

**Watch for these**, because Obsidian accepts them and the MkDocs build does not:

- **Heading links.** Obsidian writes a heading link as the heading text with spaces as `%20`, for example `registry.md#Common%20autostart%20locations`. MkDocs anchors are lower-case slugs: `registry.md#common-autostart-locations`. Fix the anchor by hand; `mkdocs build --strict` fails on anchors that do not exist.
- **Renames and new pages.** Obsidian updates links but not `nav` in `mkdocs.yml` or the browse tables. After a rename or a new page, edit `nav` and run `python tools/cc.py index`.
- **Obsidian-only syntax.** Do not use callouts (`> [!note]`), embeds (`![[page]]`), block references (`^id`), `==highlight==` or `%%comments%%`. Use MkDocs admonitions (`!!! warning`) and normal links.
- **Admonitions and content tabs** (`!!! note`, `=== "PowerShell"`) show as plain or indented text in Obsidian. That is expected; keep their four-space indentation, and check the result with `mkdocs serve`.
- **Code includes.** Lines such as `--8<-- "bash/linux-triage.sh"` are pymdownx snippets resolved from `scripts/` at build time; leave them as they are.

Run the normal checks before you commit (see [Workflow](#workflow)); Obsidian does not replace them.

## Scripts

- Live in `scripts/<language>/`, start from the templates on the language automation pages, and are documented on the matching `docs/toolbox/` page.
- Read-only by default. Anything that changes state needs `SupportsShouldProcess` (`-WhatIf`) in PowerShell or an explicit flag in Bash/Python.
- No secrets in code, arguments or examples — read tokens from the environment or a secret store.
- PowerShell scripts must pass PSScriptAnalyzer at Warning level; Bash scripts must pass `shellcheck`. Keep scripts ASCII-only so Windows PowerShell 5.1 reads them correctly without a BOM.
  CI enforces both (`lint` job in `build.yml`). Run the PowerShell gate locally with `pwsh tests/lint/Invoke-PSScriptAnalyzerGate.ps1`; it fails on any finding not in `tests/lint/pssa-baseline.json`. Fix new findings rather than baselining them; after fixing old ones, shrink the baseline with `-UpdateBaseline`.
- Every script in `scripts/powershell/` must pass `tests/powershell/ScriptContract.Tests.ps1` (run in CI): ASCII-only, `.EXAMPLE` help, a non-mandatory `TargetEnvironment` (`Test`/`Prod`, default `Test`) that the script reads, and no live calls when run in `Test`. Add new parameters at the end of the `param()` block so positional callers keep working.

## Importing existing work

When adding existing scripts, procedures or research, do not drop them into a miscellaneous folder:

1. Identify what it is.
2. Classify it: platform, language/technology, task.
3. Find related existing entries.
4. Extract reusable commands, queries and configuration into entries.
5. Put the implementation in `scripts/` and document it in `docs/toolbox/`.
6. Link it from the relevant workflows.
7. Record the reasoning and use case.
