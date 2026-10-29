---
title: Web Application Security Testing
type: entry
platforms: [Linux, Windows]
languages: [Bash, Python]
tasks: [Assurance, Detection Engineering, Hardening]
category: Web Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-10-28
last_updated: 2026-10-28
tags: [sast, dast, iast, rasp, sca, semgrep, codeql, zap, nikto, nuclei, burp-suite, ffuf, security-testing, ci-cd-security, shift-left, dependency-check, fuzzing]
aliases: [SAST pipeline, DAST scanning, IAST instrumentation, RASP runtime protection, SCA dependency scanning, OWASP ZAP, semgrep security rules, CI/CD security testing, shift-left security, fuzz testing, parameter fuzzing, authenticated DAST, contract testing security]
difficulty: intermediate
verified: true
last_verified: 2026-10-28
---

# Web Application Security Testing
> **Created**: 2026-10-28T00:00:00Z
> **Last Modified**: 2026-10-28T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED SCOPE ONLY**
> All active scanning (DAST, fuzzing) must target applications you own or have explicit written permission to test.
> Scanning production without approval can cause downtime and legal liability.
> 1. Use a dedicated staging/test environment for active scans.
> 2. Rate-limit scans to avoid inadvertent DoS.
> 3. Document scope, methodology, and findings in the engagement record.

Comprehensive guide to SAST, SCA, DAST, IAST, and RASP for web applications, including CI/CD integration patterns and manual verification workflows.

---

## 1. Static Application Security Testing (SAST)

SAST analyses source code, bytecode, or binaries for security flaws without running the application. It finds issues early (shift-left) but generates false positives and cannot detect runtime/logic flaws.

### Semgrep (polyglot, fast, CI-friendly)

```bash
# Install
pip install semgrep

# Scan with the OWASP Top 10 + security-audit rulesets
semgrep scan --config "p/owasp-top-ten" \
             --config "p/python" \
             --config "p/security-audit" \
             --json -o semgrep-results.json \
             ./src/

# View findings summary
semgrep scan --config "p/owasp-top-ten" ./src/ --no-rewrite-rule-ids
```

**Writing a custom Semgrep rule (detect hardcoded secrets pattern):**
```yaml
# .semgrep/hardcoded-secrets.yml
rules:
  - id: hardcoded-api-key
    patterns:
      - pattern: |
          $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: '(?i)(api_key|secret|password|token|passwd)'
    message: "Potential hardcoded secret in variable '$VAR'"
    languages: [python, javascript, java]
    severity: ERROR
```

### CodeQL (GitHub Advanced Security)

```yaml
# .github/workflows/codeql.yml
name: CodeQL
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [python, javascript]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-and-quality
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

**CodeQL query example (detect SQL injection sinks):**
```ql
import python
import semmle.python.security.dataflow.SqlInjectionQuery

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@", source.getNode(), "user input"
```

---

## 2. Software Composition Analysis (SCA)

SCA identifies vulnerable open-source dependencies and licence violations.

### OWASP Dependency-Check

```bash
# Scan a Java project
dependency-check.sh \
    --project "MyApp" \
    --scan /path/to/project \
    --format HTML \
    --format JSON \
    --out reports/ \
    --failOnCVSS 7      # Fail CI if any dep has CVSS ≥ 7

# Maven plugin (pom.xml)
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7
```

### pip-audit (Python)

```bash
pip install pip-audit
pip-audit --requirement requirements.txt --output json > pip-audit-report.json
pip-audit --fix  # Auto-upgrade vulnerable packages where possible
```

### npm audit (JavaScript/Node)

```bash
npm audit --json > npm-audit-report.json
npm audit fix           # Auto-fix where non-breaking
npm audit fix --force   # Force update (may break semver)
```

### GitHub Actions SCA gate

```yaml
- name: SCA — pip-audit
  run: |
    pip install pip-audit
    pip-audit --requirement requirements.txt --output json > pip-audit.json
    # Fail if any HIGH/CRITICAL vulnerabilities
    python -c "
    import json, sys
    r = json.load(open('pip-audit.json'))
    critical = [v for d in r.get('dependencies',[]) for v in d.get('vulns',[]) if v.get('fix_versions')]
    if critical:
        print(f'{len(critical)} vulnerabilities found'); sys.exit(1)
    "
```

---

## 3. Dynamic Application Security Testing (DAST)

DAST sends HTTP requests to a running application and analyses responses for vulnerabilities. No source code access required.

### OWASP ZAP (Zed Attack Proxy)

**Baseline scan (passive — no active attacks):**
```bash
docker run -v $(pwd):/zap/wrk/:rw \
    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
    -t https://staging.example.com \
    -r zap-baseline-report.html \
    -J zap-baseline-report.json \
    -l WARN
```

**Full active scan (active attacks — staging ONLY):**
```bash
docker run -v $(pwd):/zap/wrk/:rw \
    ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
    -t https://staging.example.com \
    -r zap-full-report.html \
    -J zap-full-report.json \
    -m 5        # Max spider minutes
```

**API scan (OpenAPI / GraphQL / SOAP):**
```bash
docker run -v $(pwd):/zap/wrk/:rw \
    ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
    -t https://staging.example.com/openapi.json \
    -f openapi \
    -r zap-api-report.html \
    -J zap-api-report.json
```

**Authenticated DAST with session context:**
```python
# ZAP Python client for authenticated scanning
from zapv2 import ZAPv2

zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
# Authenticate via the application's login form
zap.users.new_user(contextid, 'testuser')
zap.users.set_authentication_credentials(contextid, userid,
    json.dumps({'username': 'testuser', 'password': 'TestPass123!'}))
zap.forcedUser.set_forced_user(contextid, userid)
zap.ascan.scan(url='https://staging.example.com', recurse=True)
```

### Nuclei — template-based scanning

```bash
# Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Scan with web-specific CVE and misconfig templates
nuclei -u https://staging.example.com \
    -t cves/ -t misconfigurations/ -t exposures/ \
    -severity medium,high,critical \
    -rate-limit 10 \
    -o nuclei-report.txt \
    -json -o nuclei-report.jsonl
```

---

## 4. Parameter Fuzzing

Fuzzing discovers undocumented endpoints, injection points, and parameter-handling bugs.

### ffuf (Fast Fuzzer)

```bash
# Directory/endpoint discovery
ffuf -u https://staging.example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -mc 200,301,302,403 \
    -t 20 \
    -rate 50 \
    -o ffuf-dirs.json -of json

# Parameter fuzzing — POST body
ffuf -u https://staging.example.com/api/login \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"FUZZ","password":"test"}' \
    -w usernames.txt \
    -mc 200 \
    -t 10 -rate 20

# Header fuzzing (e.g., X-Forwarded-For bypass attempt)
ffuf -u https://staging.example.com/admin \
    -H "X-Forwarded-For: FUZZ" \
    -w ips.txt \
    -mc 200,302
```

---

## 5. Interactive Application Security Testing (IAST)

IAST instruments the running application (JVM agent, .NET CLR profiler, Python middleware) and monitors data flows at runtime. It achieves near-zero false positives on actual code paths and does not require replay of specific payloads.

| Product | Approach | Notes |
| :--- | :--- | :--- |
| **Contrast Assess** | Java/Python/Node agent | Reports vulnerabilities in production-equivalent traffic; licensing cost |
| **Seeker (Synopsys)** | Agent-based | Strong false-positive elimination via taint tracking |
| **AppDynamics IAST** | AppDynamics agent integration | Coupled to AppDynamics APM deployment |
| **OpenTelemetry + IAST middleware** | Custom taint-tracking middleware | Open-source DIY approach; high implementation effort |

**Trade-offs:**

| Pro | Con |
| :--- | :--- |
| Low false-positive rate (only fires on executed code paths) | Agent overhead (5–15% CPU, 2–5% memory) |
| No separate scan environment required | Licensing cost (commercial products) |
| Detects logic flaws and business-logic issues | Agent must support the framework/runtime |

---

## 6. Runtime Application Self-Protection (RASP)

RASP instruments the application runtime to detect and block attacks in real time from inside the process.

**Capabilities:**
- Serialization/deserialization attack prevention (Java deserialization gadgets)
- SQL injection blocking at the DB driver level (intercepts query before execution)
- Path traversal blocking (intercepts file operations)
- Command injection blocking (intercepts `exec()` / `subprocess` calls)

**Operational trade-offs vs WAF:**

| | WAF (external) | RASP (internal) |
| :--- | :--- | :--- |
| **Deployment** | Inline proxy; no app changes | Agent in app process |
| **Context** | HTTP level; no business logic context | Full application context |
| **Bypass risk** | Header obfuscation, encoding tricks | Much harder — blocking at execution layer |
| **Overhead** | Network latency (< 1 ms for inline) | CPU/memory in-process |

---

## 7. CI/CD Security Integration Pattern

```yaml
# .github/workflows/security.yml
name: Security Gates

on: [pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: SAST — Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/owasp-top-ten p/security-audit"
          publishResults: true

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: SCA — pip-audit
        run: pip install pip-audit && pip-audit -r requirements.txt

  dast:
    runs-on: ubuntu-latest
    needs: [sast, sca]    # Only run DAST if static checks pass
    steps:
      - name: Start app
        run: docker compose up -d && sleep 15
      - name: DAST — ZAP baseline
        run: |
          docker run --network host ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py -t http://localhost:8080 -J zap.json -I
      - name: Parse ZAP results
        run: |
          python -c "
          import json, sys
          r = json.load(open('zap.json'))
          high = [a for s in r.get('site',[]) for a in s.get('alerts',[]) if a['riskcode'] == '3']
          if high:
              print(f'{len(high)} HIGH alerts'); sys.exit(1)
          "
```

**Shift-left maturity model:**

| Level | Gate | Block PR? |
| :--- | :--- | :--- |
| 0 | No security gates | — |
| 1 | SCA (known CVEs) | No (advisory) |
| 2 | SAST + SCA | Yes (HIGH+CRITICAL) |
| 3 | SAST + SCA + DAST baseline | Yes |
| 4 | + Secrets scanning (GitLeaks / GitHub secret scanning) | Yes |
| 5 | + IAST on staging, RASP in production | Yes (DAST findings) |

---

## 8. Manual Verification Workflows

### Request replay & parameter tampering (Burp Suite)

1. **Capture baseline request** — proxy browser through Burp; authenticate normally; capture a successful API call in Proxy > HTTP history.
2. **Send to Repeater** (`Ctrl+R`) — modify parameters and resend without browser involvement.
3. **Parameter tampering checklist:**
   - Increment/decrement numeric IDs (IDOR: does `GET /api/orders/1001` return another user's order?).
   - Remove required parameters (does the server return a stack trace?).
   - Inject `'`, `"`, `1=1`, `<script>` into every string field.
   - Send unexpected content-types (`Content-Type: application/xml` on a JSON endpoint).
4. **Auth boundary testing:**
   - Use `admin` endpoint with a regular-user token.
   - Replay a `DELETE` request with a stale session token after logout.
   - Replace JWT `alg: RS256` with `alg: none` and remove signature (none-algorithm attack).

### Logic flaw testing

Logic flaws require human reasoning, not automation. Focus on:

| Pattern | Test |
| :--- | :--- |
| **Price manipulation** | Submit cart with negative quantity or zero price for premium items |
| **Multi-step sequence bypass** | Skip step 2 of a 3-step checkout and POST directly to step 3 |
| **Privilege escalation** | Change `role` field in profile update request from `user` to `admin` |
| **Race condition** | Send 50 concurrent requests to spend a coupon code (should be used exactly once) |

---

## Operational Gotchas

- **ZAP baseline on SPAs** — single-page applications render content via JavaScript. ZAP's spider only crawls HTML links; use the Ajax Spider (`zap.ajaxSpider.scan`) for JavaScript-rendered routes.
- **SAST false-positive tuning** — mark false positives in Semgrep with `# nosemgrep: rule-id` or in CodeQL with a query suite exclusion file. Never suppress entire severity levels.
- **DAST and tokens** — if the app uses short-lived JWTs (< 15 min), ZAP sessions expire mid-scan. Use ZAP's session token handling and a dedicated test account with long-lived tokens or session extension.
- **Nuclei rate limiting** — default rate is 150 req/s. On small staging servers this can trigger `429` responses or cause a real DoS. Always set `-rate-limit 10` or lower for self-hosted staging.

---

## Related

- [OWASP Web Top 10](../../fundamentals/web-apps/owasp-web-top-10.md)
- [WAF Fundamentals & Tuning](waf-fundamentals-and-tuning.md)
- [Secure SDLC & DevSecOps](../../fundamentals/concepts/secure-sdlc-devsecops.md)
- [Detection-as-Code Pipeline](../../tasks/detection-engineering/detection-as-code-pipeline.md)
- [Web Application Assessment (Offensive)](../../offensive/web-application-assessment.md)
- [Web API Assessment (Offensive)](../../offensive/web-api-assessment.md)

## External Resources & White Papers

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Semgrep Rules Registry](https://semgrep.dev/r)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [ffuf GitHub](https://github.com/ffuf/ffuf)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
