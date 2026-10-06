---
title: Verb the Thing                      # e.g. "Find Listening TCP Ports" — unique, task-phrased
platforms: [Windows]                       # from tools/vocabulary.yml
languages: [PowerShell]                    # from tools/vocabulary.yml
tasks: [Incident Response, Troubleshooting]
category: Networking                       # one free-text category
tags: [tag-one, tag-two]
aliases: [other phrase people search for, command name]
difficulty: basic                          # basic | intermediate | advanced
verified: false                            # set true only after checking against vendor docs / testing
# last_verified: 2026-10-05                # required when verified: true
---

# Verb the Thing

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

One or two sentences: what this answers and why an analyst needs it.

## Do the main task

```powershell
Get-Something -Parameter Value
```

**What the output tells you:** key columns/fields and how to read them.

**What to look for:** the suspicious or broken values.

## Useful variant

```powershell
Get-Something -Parameter Value | Where-Object Property -eq 'x' | Select-Object A, B, C
```

## Important options

| Option | Effect |
| --- | --- |
| `-Option` | what it changes |

## Where is the setting?  <!-- configuration entries only; delete otherwise -->

=== "GUI"

    ```text
    Settings → Area → Page
    ```

=== "PowerShell"

    ```powershell
    Get-Setting
    ```

=== "Registry"

    ```text
    HKLM\SOFTWARE\Vendor\Key   ValueName (DWORD) = 1
    ```

=== "GPO"

    ```text
    Computer Configuration → Administrative Templates → …
    ```

## Notes

Version differences, permissions required, performance caveats, false positives.

## Related

- [Linux equivalent](../linux/page.md)
- [Workflow that uses this](../../tasks/incident-response/workflow.md)
- [Detection query](../../detection/kql/page.md)

## Sources

- [Official documentation title](https://learn.microsoft.com/...)
