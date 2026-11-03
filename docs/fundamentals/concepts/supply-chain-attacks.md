---
title: Supply Chain Attacks
type: concept
platforms: [Linux, Windows, GitHub, AWS, Azure]
languages: [Python, Bash, PowerShell]
tasks: [Threat Intelligence, Hardening, Detection Engineering, Incident Response]
category: Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, supply-chain, dependency-confusion, solarwinds, xz-utils, malicious-packages, sbom, sigstore, typosquatting, build-pipeline, open-source-risk, T1195, software-supply-chain]
aliases: [supply chain attack, software supply chain, dependency confusion, typosquatting npm, malicious package, SolarWinds, XZ backdoor, SBOM, Sigstore, open source risk, third-party risk]
difficulty: intermediate
verified: false
---

# Supply Chain Attacks
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** a supply chain attack compromises software, firmware, or hardware before it reaches the target organization — by injecting malicious code into a dependency, a build pipeline, or an update mechanism that the target trusts.

## What it is

Every piece of software your organization runs arrives through a chain of suppliers: package registries, build systems, CI/CD platforms, third-party SaaS tools, and hardware vendors. A supply chain attack breaks the integrity of that chain at any link. Instead of breaching your network directly, the attacker compromises something you trust and inherit the same level of access you grant to that trusted component.

Supply chain attacks have moved from niche concern to board-level risk. The 2020 SolarWinds Orion compromise injected a backdoor (`SUNBURST`) into a signed software update downloaded by approximately 18,000 organizations, including US government agencies. The 2024 XZ Utils backdoor was planted over two years through a sustained social-engineering effort against an open source maintainer.

## How it works

The attack surface spans every stage of the software development and delivery lifecycle:

```text
Source code  →  Build system  →  Package registry  →  Distribution  →  Runtime
    ↑               ↑                  ↑                   ↑              ↑
[Code commit] [Build server]  [Package publish]   [Update mechanism] [Runtime deps]
   T1195.001     T1195.003        T1195.002           T1195.003        T1059
```

Key attack vectors:

| Vector | Mechanism | Notable examples |
| :--- | :--- | :--- |
| **Dependency confusion** | Attacker publishes a package on a public registry with the same name as an internal private package; the build system resolves to the public (malicious) version | Alex Birsan's research; PyTorch, Apple, Microsoft affected |
| **Typosquatting** | Near-identical package name (`reqeusts` vs `requests`) exploits developer typos | Thousands of PyPI / npm cases annually |
| **Compromised maintainer** | Social-engineering or account takeover of a legitimate open source maintainer | XZ Utils (2024), event-stream npm (2018) |
| **Build pipeline injection** | Malicious code injected into the CI/CD pipeline that runs on every merge or release | SolarWinds build server compromise |
| **Poisoned update mechanism** | Legitimate software's auto-update delivers a tampered update signed with the vendor's own key | SolarWinds SUNBURST, ASUS Live Update |
| **AI/LLM model supply chain** | Poisoned model weights published to model hubs (Hugging Face); malicious serialization via `pickle` in PyTorch format | IBM research on pickle deserialization; HuggingFace incidents |

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1195](https://attack.mitre.org/techniques/T1195/) — Supply Chain Compromise (three sub-techniques: hardware, software, software dependencies) |
| **What it leads to** | Full network access with trusted credentials; long-dwell persistence; data exfiltration at scale |
| **Where defenders meet it** | Vulnerability disclosure alerts for dependencies; anomalous build pipeline behavior; SBOM review; EDR alerts on unexpected software components |

## Attack example — dependency confusion

A developer at a company uses a private package named `acme-internal-utils` hosted on the company's Artifactory instance. An attacker searches public documentation, Stack Overflow posts, or GitHub commits for the internal package name, then publishes a package with the same name to PyPI or npm with a higher version number.

When the build system resolves `acme-internal-utils`, it checks public registries first (or alongside private ones) and finds version `9.0.0` on PyPI versus `1.2.3` on Artifactory. Many package managers default to the highest version. The build downloads and executes the attacker's package.

```python
# A dependency confusion payload typically runs on install via setup.py
# This is an awareness-only representation of the technique
import subprocess, socket, os

def run_on_install():
    # Beacon back to attacker infrastructure to report the affected org
    # Real attacks used subprocess calls, DNS beacons, or reverse shells
    pass

run_on_install()
```

**Mitigation**: pin packages by exact version and hash, use a hermetic (no public network) build environment, and configure your package manager to prefer your private registry for any package in its scope.

## AI/LLM supply chain risks

Machine learning models introduce a new supply chain surface. Models distributed through Hugging Face or other hubs may contain:

- **Malicious pickle serialization**: PyTorch `.pt` files use Python's `pickle` format, which can execute arbitrary code on load. A malicious model file triggers a reverse shell or data exfiltration the moment `torch.load()` is called.
- **Poisoned training data**: model behavior is silently biased toward an attacker's desired output by manipulating training or fine-tuning datasets before they reach the training pipeline.
- **Tainted fine-tuning sets**: a rogue training sample injected into a fine-tuning dataset can embed a trigger phrase that reliably causes the model to output harmful content.

```python
# Safe model loading — use weights_only=True to prevent pickle code execution
import torch
model_state = torch.load("model.pt", weights_only=True)  # prevents arbitrary code execution
model.load_state_dict(model_state)
```

## Mitigations

Mitigations map to the specific stage of the supply chain they protect:

| Stage | Control |
| :--- | :--- |
| **Source code** | Enforce signed commits (GPG / Sigstore), enforce branch protection, multi-party code review |
| **Dependencies** | Pin exact versions with hash verification (`pip install --require-hashes`), use a private registry mirror, generate and review SBOMs |
| **Build pipeline** | Hermetic builds (no public network access during build), reproducible builds, use SLSA framework guidelines |
| **Package publish** | Sign packages with Sigstore/cosign, verify provenance before installing in production |
| **Distribution/update** | Verify signatures and checksums on every update, use HTTPS pinning, avoid auto-update without integrity check |
| **AI models** | Use `weights_only=True` in PyTorch load; verify model cards and provenance on Hugging Face; scan for known-bad hashes |

## Software Bill of Materials (SBOM)

An SBOM is a machine-readable inventory of every component in a software build — libraries, versions, licenses, and origins. US Executive Order 14028 (2021) required SBOMs for software sold to federal agencies. Key formats:

- **SPDX** (Software Package Data Exchange) — Linux Foundation standard; JSON/tag-value formats
- **CycloneDX** — OWASP-backed; designed for security and vulnerability disclosure
- **SWID** (ISO/IEC 19770-2) — primarily for enterprise software asset management

Generating an SBOM in Python:

```bash
# Generate a CycloneDX SBOM from a Python project's requirements
pip install cyclonedx-bom
cyclonedx-py environment --output-format json > sbom.json
```

## Do it

```bash
cc find "supply chain"
cc find "dependency management"
cc find "SBOM"
```

Scan your Python project's dependencies for known vulnerabilities and typosquatting risk:

```bash
# Check installed packages against the OSS vulnerability database
pip install pip-audit
pip-audit

# Review dependency tree for unexpected transitive packages
pip install pipdeptree
pipdeptree --warn fail
```

## See it

| Signal | What you see |
| :--- | :--- |
| Build logs | Package resolution pulling from an unexpected registry or an unexpectedly high version number |
| EDR | New process spawned from within a package install step; outbound network connection from `python setup.py install` |
| DNS logs | Beacon domains resolved during a build job (common in dependency confusion proofs-of-concept) |
| SBOM diff | New or changed component between consecutive builds that was not in the reviewed dependency manifest |
| HuggingFace / npm / PyPI security advisories | Malicious package reports for packages your project uses |

## Detect it

- Detection: [Sigma — CI/CD Secret Leak](../../detection/sigma/cicd-secret-leak.md)
- Hunt: [Threat Intelligence](../../tasks/threat-intelligence/index.md)
- Respond: [Incident Response](../../tasks/incident-response/index.md)
- Harden: [Hardening](../../tasks/hardening/index.md)

## Related concepts

- [Adversarial Training](adversarial-training.md)
- [Ethical Hacking](ethical-hacking.md)
- [Cloud Native Security](cloud-native-security.md)
- [Identity and Access Management](identity-access-management.md)

## External Resources & White Papers

- [MITRE ATT&CK T1195 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- [CISA — Defending Against Software Supply Chain Attacks](https://www.cisa.gov/resources-tools/resources/defending-against-software-supply-chain-attacks)
- [SLSA Framework — Supply chain Levels for Software Artifacts](https://slsa.dev/)
- [Sigstore — Keyless Signing for Software Supply Chains](https://www.sigstore.dev/)
- [NTIA — Minimum Elements for an SBOM](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
