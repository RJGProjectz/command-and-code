# CIS check catalogs (generated locally, not distributed)

Catalogs are derived from licensed CIS / Tenable material, so this folder ships empty. Build one
from audit files you are entitled to use:


python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows 11 Enterprise" --version 5.1.0 \
    --out scripts/cis/catalogs/windows11-enterprise-v5.1.0.json <..._L1.audit> <..._L2.audit>


`*.json` here and `*.audit` files are gitignored. Details: docs/tasks/hardening/windows-11-cis-audit-tool.md
