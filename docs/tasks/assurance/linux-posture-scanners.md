---
title: Scan Linux Host Posture with Lynis, OpenSCAP and osquery
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assurance, Hardening]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [posture, lynis, openscap, oscap, scap, xccdf, osquery, cis, compliance-scan, ndjson, read-only]
aliases: [lynis audit system, lynis-report.dat, lynis hardening index, oscap xccdf eval, oscap info, scap security guide, ssg datastream, oscap html report, oscap results arf, osqueryi json, osquery authorized_keys, osquery systemd_units, osquery listening_ports, osquery suid_bin, osquery sudoers, host posture scan linux, compare cis audit results]
difficulty: intermediate
verified: true
last_verified: 2026-10-20
---

# Scan Linux Host Posture with Lynis, OpenSCAP and osquery
> **Created**: 2026-10-20T20:00:00Z
> **Last Modified**: 2026-10-20T20:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Every command here only reads. Do **not** add `oscap xccdf eval --remediate` or run the
> generated fix scripts on production: they change hundreds of settings at once. Install scanners
> from the distribution or vendor repositories only, run them on a test host first, and treat the
> reports as sensitive (they list users, keys, open ports and weaknesses).

**Trigger:** you need a second opinion on a host's hardening beyond the
[Linux CIS audit tool](../hardening/linux-cis-audit-tool.md), a full SCAP compliance report for an
auditor, or a quick inventory of accounts, keys and services.

**Goal:** run three read-only scanners, turn each result into NDJSON with the same base fields as the
project's other tools, keep the HTML report as evidence, and reconcile the findings with the CIS tool.

| Scanner | Answers | Output |
| :--- | :--- | :--- |
| Lynis | broad hardening review with suggestions, hardening index | `/var/log/lynis-report.dat` (key=value) |
| OpenSCAP (`oscap`) | pass/fail per rule of a published profile (CIS, STIG, ANSSI) | XCCDF/ARF XML, HTML report |
| osquery (`osqueryi`) | what is on the host right now: users, keys, units, ports, SUID files | JSON rows |

## 1. Install (once, from the distro)

```bash
dnf install lynis openscap-scanner scap-security-guide        # RHEL family (lynis from EPEL)
apt install lynis openscap-scanner ssg-debderived             # Debian/Ubuntu (content package name varies by release)
# osquery: the vendor repository at https://osquery.io/downloads (verify the signing key)
```

## 2. Lynis

```bash
sudo lynis audit system --cronjob --report-file /var/tmp/lynis-report.dat --logfile /var/tmp/lynis.log
grep -E '^(hardening_index|warning\[\]|suggestion\[\])=' /var/tmp/lynis-report.dat | head
```

- `--cronjob` is the unattended mode (no colours, no questions). Without `--report-file`, root runs
  write `/var/log/lynis-report.dat`.
- `warning[]` and `suggestion[]` lines are `TEST-ID|message|details|solution|`. `hardening_index` is a
  0-100 score; track its trend per host, not the absolute value.
- Exit code 0 means the scan ran, not that the host is clean; code 78 appears only with
  `error-on-warnings=yes` in a custom profile.

## 3. OpenSCAP with SCAP Security Guide

```bash
ds=/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml            # pick the datastream for your OS
oscap info "$ds"                                                 # lists profiles and their IDs
oscap info --profile cis_server_l1 "$ds"                         # what that profile covers

sudo oscap xccdf eval --profile cis_server_l1 \
    --results /var/tmp/oscap-results.xml \
    --results-arf /var/tmp/oscap-arf.xml \
    --report /var/tmp/oscap-report.html \
    "$ds"
echo "exit=$?"                                                   # 0 all pass, 2 a rule failed or was unknown, 1 error
```

- The HTML report is the evidence file for an auditor; ARF is the format SCAP tools exchange.
- To rebuild the HTML later: `oscap xccdf generate report --output report.html /var/tmp/oscap-results.xml`.
- A profile suffix (`cis_server_l1`) works as well as the full ID
  (`xccdf_org.ssgproject.content_profile_cis_server_l1`).

## 4. osquery: accounts, keys and services

`osqueryi` reads the live system and returns SQL rows; `--json` prints a JSON array.

```bash
q() { sudo osqueryi --json "$1"; }

# Accounts with a login shell, and their password state
q "SELECT u.username, u.uid, u.shell, s.password_status, s.last_change
   FROM users u LEFT JOIN shadow s USING (username)
   WHERE u.shell NOT LIKE '%nologin' AND u.shell NOT LIKE '%false';"

# SSH authorized keys per user
q "SELECT u.username, k.algorithm, k.comment, k.key_file, k.options
   FROM users u JOIN authorized_keys k USING (uid);"

# Sudo rules
q "SELECT source, header, rule_details FROM sudoers;"

# Enabled or running services and the account they run as
q "SELECT id, active_state, sub_state, unit_file_state, user, fragment_path
   FROM systemd_units WHERE id LIKE '%.service'
   AND (active_state = 'active' OR unit_file_state = 'enabled');"

# Listening sockets with the owning process
q "SELECT l.address, l.port, l.protocol, p.name, p.path
   FROM listening_ports l JOIN processes p USING (pid) WHERE l.port > 0;"

# SUID/SGID binaries
q "SELECT path, username, groupname, permissions FROM suid_bin;"
```

Compare each list with what the host should have: the [service account audit](service-account-audit.md)
and [effective permissions review](effective-permissions-access-review.md) explain what to look for.
For continuous collection, run the same queries as a scheduled `osqueryd` pack instead of by hand.

## 5. Normalise to NDJSON

Use the GOLDEN_STANDARDS §4.7 base fields (`timestamp`, `host`, `tool`, `version`, `execution_id`) plus
`check_id`, `title` and `result`, so one SIEM search covers these and the CIS tool.

```bash
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ); host=$(hostname -s); run=$(cat /proc/sys/kernel/random/uuid)
out=/var/tmp/posture-$host.ndjson; : > "$out"

# Lynis warnings and suggestions
grep -E '^(warning|suggestion)\[\]=' /var/tmp/lynis-report.dat |
  jq -R -c --arg ts "$ts" --arg host "$host" --arg run "$run" --arg ver "$(lynis show version)" '
    capture("^(?<kind>warning|suggestion)\\[\\]=(?<id>[^|]*)\\|(?<msg>[^|]*)\\|(?<detail>[^|]*)\\|")
    | {timestamp:$ts, host:$host, tool:"lynis", version:$ver, execution_id:$run,
       check_id:.id, title:.msg, detail:.detail, result:(if .kind=="warning" then "Fail" else "Info" end)}' >> "$out"

# OpenSCAP rule results (needs xmlstarlet)
xmlstarlet sel -N x=http://checklists.nist.gov/xccdf/1.2 -t -m '//x:rule-result' \
    -v '@idref' -o '|' -v 'x:result' -n /var/tmp/oscap-results.xml |
  jq -R -c --arg ts "$ts" --arg host "$host" --arg run "$run" --arg ver "$(oscap --version | head -1)" '
    split("|") | {timestamp:$ts, host:$host, tool:"oscap", version:$ver, execution_id:$run,
       check_id:.[0], result:({"pass":"Pass","fail":"Fail","error":"Error","notapplicable":"NotApplicable",
       "notchecked":"NotChecked","notselected":"NotSelected"}[.[1]] // .[1])}
    | select(.result != "NotSelected")' >> "$out"

# osquery: one record per row (example: authorized keys)
sudo osqueryi --json "SELECT u.username, k.algorithm, k.key_file FROM users u JOIN authorized_keys k USING (uid);" |
  jq -c --arg ts "$ts" --arg host "$host" --arg run "$run" '.[] |
    {timestamp:$ts, host:$host, tool:"osquery", version:"", execution_id:$run,
     check_id:"authorized_keys", title:(.username + " " + .key_file), result:"Info", detail:.}' >> "$out"

jq -s 'group_by(.tool)[] | {tool:.[0].tool, total:length, fail:map(select(.result=="Fail"))|length}' "$out"
```

## 6. Compare with the CIS Linux audit tool (WP-58)

Run the [Linux CIS audit tool](../hardening/linux-cis-audit-tool.md) on the same host and level, then
line the CIS recommendation IDs up with the SSG rules. SSG rules carry the CIS number in a
`reference` whose `href` points to `cisecurity.org`:

```bash
sudo ./scripts/bash/audit_cis_linux.sh --level L1 --output-dir /var/tmp/cis > /dev/null

# SSG rule id -> CIS recommendation id, from the datastream
xmlstarlet sel -N x=http://checklists.nist.gov/xccdf/1.2 -t \
    -m '//x:Rule[x:reference[contains(@href,"cisecurity.org")]]' \
    -v '@id' -o '|' -v 'x:reference[contains(@href,"cisecurity.org")][1]' -n "$ds" > /var/tmp/ssg-cis-map.txt

jq -R -c 'split("|") | {rule:.[0], cis_id:.[1]}' /var/tmp/ssg-cis-map.txt > /var/tmp/ssg-cis-map.ndjson
jq -c 'select(.tool=="oscap") | {rule:.check_id, oscap:.result}' /var/tmp/posture-*.ndjson > /var/tmp/oscap-min.ndjson
jq -c '{cis_id, cc:.result}' /var/tmp/cis/cis-*.ndjson > /var/tmp/cc-min.ndjson

jq -n -c --slurpfile map /var/tmp/ssg-cis-map.ndjson --slurpfile os /var/tmp/oscap-min.ndjson --slurpfile cc /var/tmp/cc-min.ndjson '
  ($os | map({(.rule): .oscap}) | add) as $osr
  | ($map | map(select($osr[.rule])) | group_by(.cis_id) | map({(.[0].cis_id): [.[] | $osr[.rule]]}) | add) as $bycis
  | $cc[] | . + {oscap: ($bycis[.cis_id] // [])}
  | select((.oscap | length) > 0 and ((.oscap | all(. == "Pass")) != (.cc == "Pass")))'
```

The last command prints only the recommendations where the two tools disagree. Typical reasons:

| Disagreement | Usual cause |
| :--- | :--- |
| CIS tool Fail, oscap Pass | runtime vs persisted value: the CIS tool requires both (`sysctl`, sshd first-match); SSG may check one |
| CIS tool Pass, oscap Fail | SSG checks more (package state, extra files, `Match` blocks) than the CIS tool covers |
| One side has no result | the CIS tool skips manual items; SSG maps one CIS item to several rules or none |
| Benchmark versions differ | compare `benchmark_version` in the CIS NDJSON with the SSG release (`oscap info`) |

Record each confirmed difference in the host's ticket; a real gap in the CIS tool goes to the
backlog as a new check.

## 7. Verify

- [ ] All three scanners ran without changing the host (no `--remediate`; `rpm -Va` or
      [file integrity monitoring](file-integrity-monitoring.md) shows no new changes).
- [ ] `/var/tmp/oscap-report.html` opens and names the profile and datastream version.
- [ ] The NDJSON file has one object per line with `timestamp`, `host`, `tool`, `version`,
      `execution_id` on every line (`jq -s -e 'all(has("execution_id"))' "$out"`).
- [ ] Every CIS-vs-oscap disagreement from section 6 has an explanation or a ticket.
- [ ] Reports are stored with restricted permissions (`chmod 600`) and deleted from `/var/tmp`
      after upload.

ATT&CK relevance: posture scans find the weaknesses attackers use for persistence and privilege
escalation: unexpected SSH keys (**T1098.004**), SUID binaries (**T1548.001**), sudo rules
(**T1548.003**), new services (**T1543.002**) and extra accounts (**T1136.001**).

## Related

- [Linux CIS audit tool](../hardening/linux-cis-audit-tool.md)
- [Linux security baseline (CIS/NIST)](../hardening/linux-security-baseline.md)
- [Service account audit (NDJSON)](service-account-audit.md)
- [Effective permissions and access review](effective-permissions-access-review.md)
- [File integrity monitoring](file-integrity-monitoring.md)

## Sources

- [Lynis documentation](https://cisofy.com/documentation/lynis/) · [lynis(8)](https://github.com/CISOfy/lynis/blob/master/lynis.8)
- [OpenSCAP user manual](https://static.open-scap.org/openscap-1.3/oscap_user_manual.html)
- [SCAP Security Guide](https://github.com/ComplianceAsCode/content)
- [osquery table schema](https://osquery.readthedocs.io/en/stable/) · [osquery table specs](https://github.com/osquery/osquery/tree/master/specs)
