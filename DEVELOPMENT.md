# Command & Code — Internal Maintenance & Development Guide

> **Author**: RJGProjectz  
> **Repository**: [command-and-code](https://github.com/RJGProjectz/command-and-code)  
> **Public Documentation**: [rjgprojectz.github.io/command-and-code](https://rjgprojectz.github.io/command-and-code/)  
> **Scope**: Repository maintainers, automation agents, and technical contributors.

---

## 1. Overview & Architecture

Command & Code is an engineering-grade, version-controlled knowledge engine and operational field manual.

```text
command-and-code/
├── docs/                      Knowledge base source (Markdown + YAML front matter)
│   ├── platforms/             OS and cloud infrastructure documentation
│   ├── languages/             Scripting, APIs, and query languages
│   ├── detection/             KQL, SPL, S1QL, Sigma, ATT&CK mappings
│   ├── tasks/                 Ordered operational workflows (Administration, IR, Hunting)
│   ├── toolbox/               Documentation for operational scripts/
│   └── references/            Cheat sheets, event IDs, cross-platform equivalents
├── scripts/                   Production operational scripts (PowerShell, Bash, Python)
├── overrides/                 Material for MkDocs Jinja2 template overrides
├── templates/                 Scaffolding templates (workflow, knowledge-entry, query)
├── tools/
│   ├── cc.py                  Core validator, index generator & code block syntax checker
│   ├── sanitize.py            Identifier sanitizer & 206.* IP audit engine
│   └── vocabulary.yml         Controlled taxonomy registry
├── hooks/cc_meta.py           MkDocs hook: dynamic chip insertion & script downloads
├── task_ledger.ndjson         Immutable machine activity log
├── Audit/Agent_Activity.md    Human-readable governance activity log
├── mkdocs.yml                 MkDocs configuration
└── requirements.txt           Pinned dependencies for CI/CD builds
```

---

## 2. Local Development Setup

### Prerequisites
* Python 3.10+ (tested up to 3.14)
* PowerShell 5.1 / PowerShell 7+
* Bash (Linux or WSL)

### Virtual Environment Setup

```bash
# Clone repository
git clone https://github.com/RJGProjectz/command-and-code.git
cd command-and-code

# Create virtual environment
python -m venv .venv
```

Activate environment:
* **Windows (PowerShell)**: `.venv\Scripts\Activate.ps1`
* **Linux / macOS**: `source .venv/bin/activate`

Install dependencies:
```bash
pip install -r requirements.txt
```

Run local live-reload dev server:
```bash
mkdocs serve
```
Site will be available at `http://127.0.0.1:8000`.

---

## 3. Maintenance Tooling

### Repository Quality Checks

```bash
# 1. Validate front matter metadata against tools/vocabulary.yml and check browse tables
python tools/cc.py check

# 2. Syntax-check all fenced code blocks (PowerShell, Bash, Python, YAML) and scripts
python tools/cc.py code

# 3. Regenerate browse tables in-place
python tools/cc.py index

# 4. Strict MkDocs build (fails on any broken link or syntax warning)
mkdocs build --strict
```

### Identifier Sanitizer Tool (`tools/sanitize.py`)

Used to audit and enforce Golden Standards §2.4 (Scrubbing protocol):

```bash
# Scan repository for any IP addresses, hostnames, user accounts, or private domains
python tools/sanitize.py --scan

# Specifically verify zero presence of 206.* IPs
python tools/sanitize.py --check-206

# Preview proposed sanitization diff
python tools/sanitize.py --dry-run

# Execute sanitization in-place
python tools/sanitize.py --run
```

---

## 4. Content Authoring Protocol

1. Copy the appropriate template:
   - Workflows: `templates/workflow.md`
   - Knowledge entries: `templates/knowledge-entry.md`
   - Telemetry queries: `templates/query.md`
2. Ensure all metadata terms (`platforms`, `languages`, `tasks`) exist in `tools/vocabulary.yml`.
3. Add the new entry to `nav` in `mkdocs.yml`.
4. Run `python tools/cc.py index` to update browse tables.
5. Verify with `python tools/cc.py check` and `python tools/sanitize.py --scan`.
6. Update `Audit/Agent_Activity.md` and `task_ledger.ndjson`.

---

## 5. GitHub Pages Deployment Protocol

Deployments are automated through `.github/workflows/deploy.yml`:
1. Push changes to branch `main`.
2. GitHub Actions executes:
   - Dependency installation
   - `python tools/cc.py check`
   - `python tools/cc.py code`
   - `mkdocs build --strict`
   - Upload and deploy to GitHub Pages
3. Monitor progress under the **Actions** tab on GitHub:
   `https://github.com/RJGProjectz/command-and-code/actions`
