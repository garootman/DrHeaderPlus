# DrHeaderPlus Examples

Practical recipes for integrating DrHeaderPlus into CI/CD pipelines, test suites, and automation scripts.

## Contents

* [GitHub Actions — Security Header Gate](#github-actions--security-header-gate)
* [GitLab CI — Security Header Gate](#gitlab-ci--security-header-gate)
* [pytest — Assert No High-Severity Findings](#pytest--assert-no-high-severity-findings)
* [Pre-Deploy Gate Script](#pre-deploy-gate-script)
* [Programmatic Scanning and Filtering](#programmatic-scanning-and-filtering)
* [JSON Export for Dashboards](#json-export-for-dashboards)
* [Custom Rules with Merge](#custom-rules-with-merge)
* [OWASP ASVS V14 Compliance Check](#owasp-asvs-v14-compliance-check)
* [Multi-URL Bulk Scan](#multi-url-bulk-scan)
* [Scanning Behind Authentication](#scanning-behind-authentication)

## GitHub Actions — Security Header Gate

Add this job to your workflow to block deployments when security headers are missing or misconfigured. The CLI exits with code 70 when findings exist, which fails the step automatically.

```yaml
# .github/workflows/security-headers.yml
name: Security Header Audit

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  audit-headers:
    runs-on: ubuntu-latest
    steps:
      - name: Install DrHeaderPlus
        run: pip install drheaderplus

      - name: Scan production endpoint
        run: drheader scan single https://your-app.example.com --output json

      - name: Scan with OWASP ASVS V14 preset
        run: drheader scan single https://your-app.example.com --preset owasp-asvs-v14

      - name: Scan staging (allow self-signed certs)
        run: drheader scan single https://staging.example.com --verify false

      - name: Generate JUnit report
        if: always()
        run: drheader scan single https://your-app.example.com --junit

      - name: Upload JUnit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-headers-junit
          path: reports/junit.xml
```

### With a custom ruleset stored in the repo

```yaml
      - uses: actions/checkout@v4

      - name: Install DrHeaderPlus
        run: pip install drheaderplus

      - name: Scan with custom rules merged with defaults
        run: drheader scan single https://your-app.example.com --rules-file custom_rules.yml --merge
```

## GitLab CI — Security Header Gate

```yaml
# .gitlab-ci.yml
security-headers:
  stage: test
  image: python:3.12-slim
  script:
    - pip install drheaderplus
    - drheader scan single $APP_URL --output json
  artifacts:
    when: always
    reports:
      junit: reports/junit.xml
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### With JUnit report

```yaml
security-headers:
  stage: test
  image: python:3.12-slim
  script:
    - pip install drheaderplus
    - drheader scan single $APP_URL --junit
  artifacts:
    when: always
    reports:
      junit: reports/junit.xml
```

## pytest — Assert No High-Severity Findings

Use DrHeaderPlus in your existing test suite to enforce security headers as part of your integration tests.

### Fail on any finding

```python
# tests/test_security_headers.py
from drheader import Drheader

PRODUCTION_URL = "https://your-app.example.com"

def test_no_security_header_issues():
    """All security headers must pass default rules."""
    scanner = Drheader(url=PRODUCTION_URL)
    findings = scanner.analyze()
    assert findings == [], f"Security header violations: {[f.to_dict() for f in findings]}"
```

### Fail only on high-severity findings

```python
def test_no_high_severity_header_issues():
    """No high-severity security header violations allowed."""
    scanner = Drheader(url=PRODUCTION_URL)
    findings = scanner.analyze()
    high = [f for f in findings if f.severity == "high"]
    assert high == [], f"High-severity violations: {[f.to_dict() for f in high]}"
```

### Test multiple endpoints with parametrize

```python
import pytest
from drheader import Drheader

ENDPOINTS = [
    "https://your-app.example.com",
    "https://your-app.example.com/api/health",
    "https://your-app.example.com/login",
]

@pytest.mark.parametrize("url", ENDPOINTS)
def test_security_headers(url):
    scanner = Drheader(url=url)
    findings = scanner.analyze()
    high = [f for f in findings if f.severity == "high"]
    assert high == [], f"{url}: {[f.to_dict() for f in high]}"
```

### Test with OWASP ASVS V14 preset

```python
from drheader import Drheader
from drheader.utils import preset_rules

def test_owasp_asvs_v14_compliance():
    """Endpoint must pass OWASP ASVS V14 header requirements."""
    rules = preset_rules("owasp-asvs-v14")
    scanner = Drheader(url="https://your-app.example.com")
    findings = scanner.analyze(rules=rules)
    assert findings == [], f"ASVS V14 violations: {[f.to_dict() for f in findings]}"
```

### Test pre-captured headers (no network)

```python
from drheader import Drheader

def test_required_headers_present():
    """Validate headers captured from a staging deploy."""
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    scanner = Drheader(headers=headers)
    findings = scanner.analyze()
    high = [f for f in findings if f.severity == "high"]
    assert high == [], f"Violations: {[f.to_dict() for f in high]}"
```

## Pre-Deploy Gate Script

A standalone script that scans your endpoint and exits non-zero on high-severity findings. Use it in any CI system or as a manual pre-deploy check.

```python
#!/usr/bin/env python3
"""Pre-deploy security header gate. Exit 1 if high-severity issues found."""

import json
import sys

from drheader import Drheader

URL = sys.argv[1] if len(sys.argv) > 1 else "https://your-app.example.com"

scanner = Drheader(url=URL)
findings = scanner.analyze()

if not findings:
    print(f"PASS: {URL} — all security headers OK")
    sys.exit(0)

high = [f for f in findings if f.severity == "high"]
medium = [f for f in findings if f.severity == "medium"]

print(f"SCAN: {URL} — {len(findings)} issues ({len(high)} high, {len(medium)} medium)")
for f in findings:
    print(f"  [{f.severity.upper()}] {f.rule}: {f.message}")

if high:
    print(f"\nFAIL: {len(high)} high-severity issues — deploy blocked")
    sys.exit(1)
else:
    print(f"\nWARN: {len(medium)} medium/low issues — deploy allowed")
    sys.exit(0)
```

Run it:

```bash
pip install drheaderplus
python gate.py https://your-app.example.com
```

## Programmatic Scanning and Filtering

### Filter findings by severity

```python
from drheader import Drheader

scanner = Drheader(url="https://example.com")
findings = scanner.analyze()

high = [f for f in findings if f.severity == "high"]
medium = [f for f in findings if f.severity == "medium"]
low = [f for f in findings if f.severity == "low"]

print(f"High: {len(high)}, Medium: {len(medium)}, Low: {len(low)}")
```

### Filter findings by header name

```python
from drheader import Drheader

scanner = Drheader(url="https://example.com")
findings = scanner.analyze()

csp_issues = [f for f in findings if f.rule.startswith("Content-Security-Policy")]
cookie_issues = [f for f in findings if f.rule.startswith("Set-Cookie")]
```

### Access Finding fields

```python
from drheader import Drheader

scanner = Drheader(url="https://example.com")
findings = scanner.analyze()

for f in findings:
    print(f"Rule:     {f.rule}")
    print(f"Message:  {f.message}")
    print(f"Severity: {f.severity}")
    if f.value:
        print(f"Value:    {f.value}")
    if f.expected:
        print(f"Expected: {f.expected}")
    if f.avoid:
        print(f"Avoid:    {f.avoid}")
    print()
```

### Convert findings to dicts

```python
from drheader import Drheader

scanner = Drheader(url="https://example.com")
findings = scanner.analyze()

# Single finding to dict (omits None fields)
finding_dict = findings[0].to_dict()

# All findings to list of dicts
all_dicts = [f.to_dict() for f in findings]
```

## JSON Export for Dashboards

```python
import json
from drheader import Drheader

scanner = Drheader(url="https://example.com")
findings = scanner.analyze()

report = {
    "url": "https://example.com",
    "total": len(findings),
    "high": len([f for f in findings if f.severity == "high"]),
    "medium": len([f for f in findings if f.severity == "medium"]),
    "low": len([f for f in findings if f.severity == "low"]),
    "passed": len(findings) == 0,
    "findings": [f.to_dict() for f in findings],
}

with open("security_headers_report.json", "w") as f:
    json.dump(report, f, indent=2)
```

CLI equivalent:

```bash
drheader scan single --output json https://example.com > report.json
```

## Custom Rules with Merge

Load a custom YAML ruleset and merge it with the built-in defaults. Custom rules override matching defaults; new rules are appended.

### From a file

```python
from drheader import Drheader
from drheader.utils import load_rules

# Custom rules override defaults for matching headers, new ones are added
rules = load_rules(rules_file=open("my_rules.yml"), merge_default=True)

scanner = Drheader(url="https://example.com")
findings = scanner.analyze(rules=rules)
```

### From a remote URI

```python
from drheader.utils import load_rules

rules = load_rules(
    rules_uri="https://raw.githubusercontent.com/your-org/security-policy/main/headers.yml",
    merge_default=True,
)
```

### Custom rules without merging (replace defaults entirely)

```python
from drheader.utils import load_rules

rules = load_rules(rules_file=open("strict_rules.yml"))
# Only headers defined in strict_rules.yml are checked
```

### Example custom rules YAML

```yaml
# my_rules.yml — override CSP and add a custom header check
Content-Security-Policy:
  Required: True
  Must-Avoid:
    - unsafe-inline
    - unsafe-eval
  Directives:
    Default-Src:
      Required: True
      Value-One-Of:
        - none
        - self
    Script-Src:
      Required: True
      Must-Avoid:
        - unsafe-inline

# Enforce a stricter HSTS max-age (1 year)
Strict-Transport-Security:
  Required: True
  Must-Contain:
    - includeSubDomains
    - preload
  Directives:
    max-age:
      Required: True
      Value-Gte: 31536000

# Flag a custom internal header that should not leak
X-Internal-Debug:
  Required: False
  Severity: high
```

CLI equivalent:

```bash
drheader scan single https://example.com --rules-file my_rules.yml --merge
```

## OWASP ASVS V14 Compliance Check

The built-in OWASP ASVS V14 preset covers response-header requirements from [ASVS 4.0 V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md).

### Python

```python
from drheader import Drheader
from drheader.utils import preset_rules

rules = preset_rules("owasp-asvs-v14")
scanner = Drheader(url="https://example.com")
findings = scanner.analyze(rules=rules)

for f in findings:
    print(f"[{f.severity.upper()}] {f.rule}: {f.message}")
```

### CLI

```bash
drheader scan single --preset owasp-asvs-v14 https://example.com
drheader scan single --preset owasp-asvs-v14 --output json https://example.com
```

### Headers checked by the OWASP ASVS V14 preset

| ASVS ID | Header | Validation |
|:--------|:-------|:-----------|
| V14.4.3 | Content-Security-Policy | Required; must-avoid unsafe-inline, unsafe-eval; default-src none/self |
| V14.4.4 | X-Content-Type-Options | Required; value: nosniff |
| V14.4.5 | Strict-Transport-Security | Required; includeSubDomains; max-age >= 15724800 |
| V14.4.6 | Referrer-Policy | Required; one-of: strict-origin, strict-origin-when-cross-origin, no-referrer |
| V14.4.7 | X-Frame-Options | Required; DENY or SAMEORIGIN |
| V14.5.3 | Access-Control-Allow-Origin | Optional; must-avoid * and null |

## Multi-URL Bulk Scan

### CLI — text file (one URL per line)

```bash
# urls.txt
# https://app.example.com
# https://api.example.com
# https://admin.example.com

drheader scan bulk urls.txt --file-format txt --output json
```

### CLI — JSON file (with per-target request config)

```json
[
    {"url": "https://app.example.com"},
    {"url": "https://api.example.com", "method": "GET"},
    {"url": "https://admin.example.com", "timeout": 15, "verify": false}
]
```

```bash
drheader scan bulk targets.json --output json
```

### Python — scan multiple URLs programmatically

```python
from drheader import Drheader

urls = [
    "https://app.example.com",
    "https://api.example.com",
    "https://admin.example.com",
]

for url in urls:
    scanner = Drheader(url=url)
    findings = scanner.analyze()
    status = "PASS" if not findings else f"FAIL ({len(findings)} issues)"
    print(f"{url}: {status}")
```

## Scanning Behind Authentication

### Bearer token

```python
from drheader import Drheader

scanner = Drheader(
    url="https://api.example.com/protected",
    headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIs..."},
)
findings = scanner.analyze()
```

### Custom cookies

```python
from drheader import Drheader

scanner = Drheader(
    url="https://app.example.com/dashboard",
    cookies={"session_id": "abc123", "csrf_token": "xyz789"},
)
findings = scanner.analyze()
```

### Skip SSL verification (staging/internal)

```python
from drheader import Drheader

scanner = Drheader(url="https://staging.internal.example.com", verify=False)
findings = scanner.analyze()
```

### Custom timeout

```python
from drheader import Drheader

scanner = Drheader(url="https://slow-endpoint.example.com", timeout=30)
findings = scanner.analyze()
```

### POST method instead of HEAD

```python
from drheader import Drheader

scanner = Drheader(url="https://api.example.com/health", method="POST")
findings = scanner.analyze()
```
