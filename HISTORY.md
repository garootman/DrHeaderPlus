# Changelog

## 3.0.2 (2025-02-13)

Stable release of DrHeaderPlus — a modernized fork of [drHEADer](https://github.com/Santandersecurityresearch/DrHeader).

### Build & Tooling
- Replaced Poetry + tox with uv + hatchling (PEP 621)
- Python 3.12+ only (dropped 3.8–3.11)
- Replaced unmaintained `junit-xml` with `junitparser`
- Ruff linter with pyupgrade (`UP`), isort (`I`), and bandit (`S`) rules
- CI: GitHub Actions with uv, test matrix for Python 3.12 & 3.13
- Release: tag-triggered `uv build` + `uv publish` to PyPI

### Code Modernization
- Full type annotations across all modules (PEP 561 `py.typed` marker)
- `Finding` and `ReportItem` dataclasses replace ad-hoc dicts
- `Drheader.analyze()` returns `list[Finding]` with `to_dict()` for serialization
- Modern Python 3.12+ syntax throughout (`str | None`, `match`, f-strings)

### Security Ruleset
- Per-rule severities (high / medium / low) aligned with OWASP Secure Headers Project
- New required headers: `Permissions-Policy`, `Cross-Origin-Resource-Policy`, `X-Permitted-Cross-Domain-Policies`
- `Pragma` downgraded to optional (deprecated HTTP/1.0 legacy)
- `X-XSS-Protection` value changed to `0` (OWASP recommendation — disable the filter)
- CSP directive-level rules: `script-src`, `style-src`, `object-src`, `form-action`, `base-uri`, `frame-ancestors`
- CSP top-level must-avoid expanded: `data:`, `http:`, `ftp:` schemes
- `Access-Control-Allow-Origin`: optional, must-avoid `*`
- Leak headers: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, `X-Client-IP`, `X-Forwarded-For`, `User-Agent`

### Advanced Validation
- HSTS `max-age` threshold check via new `value-gte` validator (>= 6 months / 15552000s)
- CSP nonce/hash awareness: `unsafe-inline` suppressed when nonces or hashes are present
- CSP `strict-dynamic` support: scheme sources and `self` ignored when `strict-dynamic` + nonce/hash present
- `Content-Security-Policy-Report-Only` without enforcing CSP flagged as high severity
- `SameSite=None` cookies without `Secure` flag detected
- CORS active origin reflection probe in scan mode (spoofed `Origin` header)
- Cross-origin isolation headers (COEP/COOP) opt-in via `cross_origin_isolated` flag

### Testing
- 151 tests with 94% coverage
- 20+ new integration tests for updated security rules

## 0.1.0 (2019-07-18)

- First release (as drHEADer by Santander UK Security Engineering)
