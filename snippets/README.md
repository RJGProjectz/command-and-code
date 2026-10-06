# snippets/

Raw, copy-ready fragments — one query or code block per file — for use **outside** the documentation:
pasting into a SIEM, loading into a script, or (later) feeding an indexer.

```text
snippets/
├── powershell/   *.ps1
├── bash/         *.sh
├── python/       *.py
├── kql/          *.kql
├── spl/          *.spl
└── s1ql/         *.s1ql
```

## Rules

- The documentation in `docs/` is the source of truth. A snippet is an extract of a documented query, not a new one — every snippet must have a matching entry, and the entry should name the snippet file.
- Name files after the documentation heading: `kql/encoded-powershell.kql`.
- First line is a comment with the source page: `// docs/detection/kql/process-events.md#encoded-powershell`.
- Complete, reusable programs belong in `scripts/`, not here.

`kql/encoded-powershell.kql` is the reference example. Other folders start empty on purpose: extract snippets when you have a real use for them, rather than duplicating every query up front.
