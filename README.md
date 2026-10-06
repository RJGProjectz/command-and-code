# Command & Code

> **Command & Code — The practical security operations field manual.**

A version-controlled knowledge base of **commands, code, queries, configuration locations, investigation procedures, detections and automation** for security operations — written so an analyst can go from *"how do I…?"* to a copy-ready answer in seconds.

The repository is the product. The website is a generated view of it.

---

## Why it exists

Security work depends on hundreds of small, precise facts: the right `Get-WinEvent` filter, the Linux equivalent of a PowerShell command, the KQL table that holds registry events, the GPO path for command-line auditing, the event ID for a new service. They are usually scattered across browser bookmarks, old tickets and memory.

Command & Code puts them in one place that is:

- **Searchable** — think of a problem, search, copy the answer.
- **Connected** — every entry is reachable by **Platform**, **Language/Technology** and **Task**, and workflows link to the entries instead of duplicating them.
- **Honest about accuracy** — every page declares whether it is verified; unverified content says so on the page.
- **Portable** — plain Markdown and scripts in Git. Useful offline, in VS Code, on GitHub, or as the generated site.

## Intended users

Security analysts, incident responders, threat hunters, detection engineers and security administrators working across Windows, Linux, Microsoft 365, Splunk and SentinelOne.

## Information architecture

```text
Platform  ──┐
Language  ──┼──▶  one entry, discoverable three ways
Task      ──┘
```

| Dimension | Examples |
| --- | --- |
| Platform | Windows · Linux · Microsoft 365 (Defender, Entra, Intune, Exchange) · Virtualization |
| Language / Technology | PowerShell · Bash · Python · Windows CLI · KQL · SPL · S1QL · Sigma · MITRE ATT&CK |
| Task | Incident Response · Threat Hunting · Investigation · Troubleshooting · Administration · Detection Engineering · Hardening · Forensics · Automation |

Each page lives in **one** place (usually under its platform or detection language). Front matter declares its other dimensions, and the browse pages for every language and task are **generated** from that metadata — so nothing is duplicated.

Content types:

| Type | What it is |
| --- | --- |
| `entry` | Reference knowledge: commands, queries, configuration locations — each with *why*, options, output and what to look for |
| `workflow` | Ordered field procedure (e.g. *Suspicious PowerShell Investigation*) that links to entries |
| `tool` | Documentation for a script in `scripts/` |
| `reference` | Lookup tables (event IDs, cross-platform equivalents, ATT&CK mapping) |

## Repository structure

```text
command-and-code/
├── docs/                      Knowledge base (Markdown + YAML front matter)
│   ├── index.md               Homepage
│   ├── platforms/             Windows, Linux, Microsoft 365, Virtualization
│   ├── languages/             PowerShell, Bash, Python, Windows CLI
│   ├── detection/             KQL, SPL, S1QL, Sigma, MITRE ATT&CK
│   ├── tasks/                 Workflows and generated task indexes
│   ├── toolbox/               Documentation for scripts/
│   ├── references/            Event IDs, equivalents, metadata conventions, tags
│   └── roadmap.md
├── scripts/                   Reusable tools (PowerShell, Bash, Python)
├── snippets/                  Raw query/code fragments for use outside the docs
├── templates/                 knowledge-entry.md, query.md, workflow.md
├── tools/
│   ├── cc.py                  Validator, browse-table generator, code-block syntax checker
│   └── vocabulary.yml         Controlled vocabulary for platforms / languages / tasks
├── hooks/cc_meta.py           MkDocs hook: metadata chips, script downloads
├── .github/workflows/         build.yml (PR validation), deploy.yml (GitHub Pages)
├── mkdocs.yml
└── requirements.txt
```

## Local development

```bash
git clone https://github.com/YOUR-GITHUB-USER/command-and-code.git
cd command-and-code
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
```

Linux / macOS:

```bash
source .venv/bin/activate
```

Then:

```bash
pip install -r requirements.txt
mkdocs serve
```

Open <http://127.0.0.1:8000>. The site reloads as you edit.

### Checks (the same ones CI runs)

```bash
python tools/cc.py check          # front matter + browse tables up to date
python tools/cc.py code           # parse every PowerShell/Bash/Python/YAML block and script (PowerShell needs pwsh on PATH)
mkdocs build --strict             # any warning, broken link or broken anchor fails
```

## Adding entries

1. Copy a template from `templates/` into the right folder under `docs/`.
2. Fill in the front matter using values from `tools/vocabulary.yml`.
3. Write task-phrased headings (*Find listening ports*) — they become link anchors and search hits.
4. Add the page to `nav` in `mkdocs.yml`.
5. Run `python tools/cc.py index` to refresh the generated browse tables.
6. Run the checks above, then open a pull request.

Full conventions: [`docs/references/metadata.md`](docs/references/metadata.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Verification expectations

Accuracy matters more than volume. Nothing in this repository should be invented.

| Front matter | Meaning |
| --- | --- |
| `verified: true` + `last_verified` | Checked against vendor documentation; code blocks pass `tools/cc.py code`. Still test in your environment. |
| `verified: false` | Not yet confirmed (vendor syntax that varies by version, environment-specific field names). The page shows **VERIFY BEFORE PRODUCTION USE**. |

In V1, **S1QL** pages and the environment-dependent **SPL** pages are marked unverified until tested against real consoles and indexes.

## GitHub Pages deployment

1. Push the repository to GitHub.
2. Replace `YOUR-GITHUB-USER` in `mkdocs.yml` (`site_url`, `repo_url`) and in this README.
3. **Settings → Pages → Build and deployment → Source: GitHub Actions.**
4. Push to `main`. `deploy.yml` validates, builds and publishes the site.

`build.yml` runs on every pull request and push: metadata validation, code-block syntax checks, PSScriptAnalyzer, and a strict MkDocs build. Protect `main` with a required status check on **Build** to block broken docs from merging.

## Contribution process

Branch → add or edit content from a template → run the checks → pull request → `Build` passes → merge → `Deploy` publishes. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Roadmap

| Phase | Status |
| --- | --- |
| 1. Foundation — structure, site, search, metadata, initial content, CI | 🟡 In progress |
| 2. Knowledge expansion — coverage, decision trees, ATT&CK relationships | 🔵 Planned |
| 3. Automation & tooling integration — existing scripts as documented tools | 🔵 Planned |
| 4. API & platform integration — Graph, Defender, Entra, Intune, Splunk, SentinelOne | 🔵 Planned |
| 5. Operational playbooks | 🔵 Planned |
| 6. Intelligent search & local AI (Ollama, grounded in this repo) | ⚪ Future |
| 7. Operational security toolkit | ⚪ Future |

Details: [`docs/roadmap.md`](docs/roadmap.md).

## License

[MIT](LICENSE)
