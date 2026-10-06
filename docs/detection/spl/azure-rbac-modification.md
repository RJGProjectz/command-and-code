---
title: Splunk Detection — Suspicious Azure RBAC Modification
type: entry
platforms:
  - Azure
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - azure
  - rbac
  - privilege-escalation
---

# Splunk Detection — Suspicious Azure RBAC Modification

Detects unauthorized assignment of high-privilege roles (e.g. `Owner`, `User Access Administrator`) to user accounts or service principals in Azure subscriptions.

## Detection Logic

```spl
index=azure_activity operationName="Microsoft.Authorization/roleAssignments/write"
| spath input=properties path=requestbody.properties.roleDefinitionId output=role_id
| search role_id="*8e3af657-a8ff-443c-a75c-2fe8c4bcb635*" OR role_id="*18d7d88d-d35e-4fb5-a5f3-7702510d2926*"
| table _time, caller, role_id, target_resource, status
```
