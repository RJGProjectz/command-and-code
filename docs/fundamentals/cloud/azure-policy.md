---
title: Fundamentals — Azure Policy & Governance Baselines
type: entry
platforms:
  - Azure
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - azure
  - azure-policy
  - governance
  - compliance
---

# Fundamentals — Azure Policy & Governance Baselines

Azure Policy enforces organizational standards and assesses cloud resource compliance at scale across subscriptions and management groups.

## 1. Effect Types

| Effect | Execution Stage | Action |
| :--- | :--- | :--- |
| `Audit` | Post-provisioning | Logs a non-compliant flag in Azure Resource Graph |
| `Deny` | Pre-provisioning | Blocks the deployment request before resource is created |
| `DeployIfNotExists` | Post-provisioning | Automatically provisions missing extensions (e.g. Log Analytics agent) |
| `Modify` | Pre-provisioning | Injects tags or forces parameters (e.g. enforce TLS 1.2 minimum) |
