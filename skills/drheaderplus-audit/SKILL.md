---
name: drheaderplus-audit
description: |
  Audit HTTP security headers using DrHeaderPlus. Use when the user asks to
  check, scan, or audit security headers for a URL or a set of headers.
  Covers CSP, HSTS, X-Frame-Options, Permissions-Policy, cookie flags,
  CORS misconfiguration, and 20+ other checks. Supports OWASP ASVS V14 preset.
license: Apache-2.0
compatibility: |
  Requires Python >=3.12 and the drheaderplus package (pip install drheaderplus).
allowed-tools: Bash(pip:*) Bash(uv:*) Bash(drheader:*) Bash(python:*)
metadata:
  author: garootman
  version: "3.0.3"
---

# DrHeaderPlus — Security Header Auditing

You are an expert at auditing HTTP security response headers using DrHeaderPlus.

## Installation

If `drheaderplus` is not installed, install it:

```bash
pip install drheaderplus
# or with uv:
uv pip install drheaderplus
```

## Quick scan (CLI)

### Scan a single URL

```bash
drheader scan single https://example.com
```

JSON output:

```bash
drheader scan single https://example.com --output json
```

### Scan with OWASP ASVS V14 preset

```bash
drheader scan single https://example.com --preset owasp-asvs-v14
```

### Scan with cross-origin isolation checks (COEP/COOP)

```bash
drheader scan single https://example.com --cross-origin-isolated
```

### Scan multiple URLs from a file

Create `urls.txt` (one URL per line) or `urls.json`:

```bash
drheader scan bulk urls.txt --file-format txt --output json
drheader scan bulk urls.json --output json
```

JSON format for bulk scan:

```json
[{"url": "https://example.com"}, {"url": "https://other.com"}]
```

### Compare pre-captured headers

```bash
drheader compare single headers.json --output json
```

Where `headers.json` contains a header dict like `{"Content-Security-Policy": "default-src 'self'", ...}`.

## Programmatic usage (Python)

When the user wants to integrate into a script or needs more control:

### Scan a URL

```python
from drheader import Drheader

scanner = Drheader(url="https://example.com")
findings = scanner.analyze()

for f in findings:
    print(f.to_dict())
```

### Analyze pre-captured headers

```python
from drheader import Drheader

headers = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
}
scanner = Drheader(headers=headers)
findings = scanner.analyze()
```

### Use OWASP ASVS V14 preset

```python
from drheader import Drheader
from drheader.utils import preset_rules

rules = preset_rules("owasp-asvs-v14")
scanner = Drheader(url="https://example.com")
findings = scanner.analyze(rules=rules)
```

### Use custom rules (from file or URI)

```python
from drheader import Drheader
from drheader.utils import load_rules

# From file
rules = load_rules(rules_file=open("my_rules.yml"))

# From URI, merged with defaults
rules = load_rules(rules_uri="https://example.com/rules.yml", merge_default=True)

scanner = Drheader(url="https://example.com")
findings = scanner.analyze(rules=rules)
```

### Pass requests kwargs (timeout, auth, custom headers, method)

```python
scanner = Drheader(
    url="https://example.com",
    headers={"Authorization": "Bearer token123"},
    timeout=10,
    verify=False,
    method="get",
)
findings = scanner.analyze()
```

## Finding structure

Each finding is a dataclass with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `rule` | `str` | Header or directive name (e.g. `"Content-Security-Policy"`, `"Set-Cookie - session_id"`) |
| `message` | `str` | Human-readable error description |
| `severity` | `str` | `"high"`, `"medium"`, or `"low"` |
| `value` | `str \| None` | Actual header value observed |
| `expected` | `list[str] \| None` | Expected values |
| `avoid` | `list[str] \| None` | Disallowed values found |
| `anomalies` | `list[str] \| None` | Unexpected values detected |
| `delimiter` | `str \| None` | Multi-value delimiter (when relevant) |

Use `finding.to_dict()` for JSON-serializable output (omits None fields).

## Cross-header checks (automatic)

These run automatically after rule-based validation:

1. **SameSite=None without Secure** — cookies with `SameSite=None` must have `Secure` flag
2. **CSP Report-Only without enforcing CSP** — `Content-Security-Policy-Report-Only` without a `Content-Security-Policy` header
3. **CORS origin reflection** — probes for `Access-Control-Allow-Origin` reflecting arbitrary origins (scan mode only, sends a spoofed `Origin` header)

## JUnit report generation

For CI/CD integration:

```bash
drheader scan single https://example.com --junit
# Creates reports/junit.xml
```

## Interpreting results

- **Exit code 0**: no issues found
- **Exit code non-zero**: issues found (or errors)
- **Empty findings list** (`[]`): all headers pass validation
- Severity levels map to remediation urgency: `high` = fix immediately, `medium` = fix soon, `low` = consider fixing

## Custom rules format (YAML)

```yaml
Content-Security-Policy:
  Required: true
  Severity: high
  Must-Contain:
    - "default-src"
    - "script-src"
  Must-Avoid:
    - "unsafe-inline"
    - "unsafe-eval"
  Directives:
    script-src:
      Required: true
      Severity: high
      Must-Avoid:
        - "unsafe-inline"
```

Rule keys: `Required` (true/false/optional), `Value`, `Value-Any-Of`, `Value-One-Of`, `Value-Gte`, `Must-Avoid`, `Must-Contain`, `Must-Contain-One`, `Severity` (high/medium/low), `Directives` (nested), `Cookies` (nested for Set-Cookie).
