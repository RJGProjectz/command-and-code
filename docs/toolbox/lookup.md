---
title: Command & Code CLI Lookup Utility
type: tool
platforms:
  - Windows
  - Linux
languages:
  - Python
tasks:
  - Administration
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - cli
  - search
  - lookup
  - offline
---

# Command & Code Terminal Companion CLI (`cc`)

Fast offline terminal companion CLI for searching knowledge nodes, viewing runbooks, extracting copy-ready command blocks, and executing production automation scripts directly from PowerShell, CMD, or Bash without needing a web browser or network connection.

---

## 1. Purpose & Capabilities

- **Instant Offline Search (`cc find`)**: Search through 263+ knowledge entries by keyword, task, platform, or language with ANSI-colored relevance scoring.
- **Runbook Viewer & Code Extraction (`cc view`)**: Pretty-print any entry directly in your terminal, or extract only executable code blocks with `--code`.
- **Direct Clipboard Copy (`cc copy`)**: Copy specific command blocks directly to the OS clipboard without touching a mouse.
- **Script Discovery & Execution (`cc scripts`, `cc run`)**: Discover and run cataloged PowerShell, Bash, and Python production scripts.
- **Environment Doctor (`cc doctor`)**: Audit local runtime health, Git status, PowerShell version, and schema compliance.
- **Grounded Answers (`cc ask`)**: Ask a question in plain words; a local Ollama model answers from the top matching pages only and cites them as `[1]`, `[2]`. The source list shows each page's path, whether it is verified, and whether the answer cited it. Answers that cite nothing are flagged **UNCITED**. Models whose name ends in `-cloud` are never picked automatically, so the question stays on this machine. Without Ollama, the sources are listed on their own.

---

## 2. Command Line Reference

```bash
# 1. Search knowledge entries by keywords
cc find "listening ports"
cc find "ransomware" --platform Windows --language PowerShell

# 2. View guide content or extract code blocks
cc view windows-connectivity
cc view ransomware-host-isolation --code

# 3. Copy a specific code block directly to clipboard
cc copy ransomware-host-isolation --block 1

# 4. List and execute cataloged automation scripts
cc scripts vpn
cc run FUNC_PS_TEST_VPN_CONNECTION

# 5. Environment & repository health audit
cc doctor

# 6. Grounded answer from a local model, with cited sources
cc ask how do I find public gcs buckets
cc ask -k 5 -m gemma3:12b "revoke a leaked service account key"   # or set CC_ASK_MODEL
```

**Measuring answer quality.** `tools/ask_eval.py` scores `cc ask` against 32 real questions in
`tests/eval/ask_questions.yml`, each with the pages that should answer it. Retrieval (hit@1, hit@5,
MRR) runs offline and in CI, which fails below 95 % hit@5. `--live` also asks the local model and checks
that each answer cites a source, cites only sources that exist, and cites an expected page.

```bash
python tools/ask_eval.py                     # retrieval scores, lists the misses
python tools/ask_eval.py --live --save-answers answers.jsonl   # ask the local model too (slow)
python tools/ask_eval.py --answers answers.jsonl                # re-score saved answers offline
```

---

## 3. Shell Integration

To use `cc` globally from any directory:

### Windows PowerShell
Add this function to your PowerShell profile (`$PROFILE`):
```powershell
function cc { & "g:\AI-Playground\C&C\command-and-code\tools\cc.cmd" @args }
```

### Linux / macOS Bash
Add an alias to your `~/.bashrc` or `~/.zshrc`:
```bash
alias cc="/path/to/command-and-code/tools/cc.sh"
```
