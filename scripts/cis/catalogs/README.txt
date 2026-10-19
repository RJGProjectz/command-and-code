# CIS check catalogs

windows11-enterprise-v5.1.0.json ships with the repository (486 checks: recommendation IDs, titles and
the settings checked; no CIS rationale or remediation text). Build a catalog for another benchmark
version from the Tenable audit files for it:

python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows 11 Enterprise" --version 5.1.0     --out scripts/cis/catalogs/windows11-enterprise-v5.1.0.json <..._L1.audit> <..._L2.audit>

Windows Server: one catalog per profile, from the _L1_MS + _L2_MS (or _L1_DC + _L2_DC) files, named
windows-server-<release>-ms-v<version>.json / -dc-, so the runner finds it by host role:

python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows Server 2025" --version 2.1.0     --out scripts/cis/catalogs/windows-server-2025-ms-v2.1.0.json <..._L1_MS.audit> <..._L2_MS.audit>

Downloaded *.audit files are gitignored. Details: docs/tasks/hardening/windows-11-cis-audit-tool.md, docs/tasks/hardening/windows-server-cis-audit-tool.md
