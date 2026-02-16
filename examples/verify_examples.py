#!/usr/bin/env python3
"""Verify that all testable code snippets from EXAMPLES.md actually work.

Note: Online tests use verify=False to avoid local SSL cert issues.
The examples themselves use the default (verify=True) which is correct
for production — we only disable here for CI/local testing.
"""

import io
import json
import subprocess
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

import urllib3

# Suppress InsecureRequestWarning for verify=False usage in tests
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

URL = "https://example.com"
PASS = 0
FAIL = 0


def check(label: str, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  PASS  {label}")
    except Exception as e:
        FAIL += 1
        print(f"  FAIL  {label}: {e}")


# ---------------------------------------------------------------------------
# 1. Offline Python examples (Drheader with headers=dict)
# ---------------------------------------------------------------------------
print("\n=== Offline Python examples ===")


def test_precaptured_headers():
    from drheader import Drheader

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
    assert isinstance(findings, list), f"Expected list, got {type(findings)}"
    assert isinstance(high, list)


check("Pre-captured headers analysis", test_precaptured_headers)


def test_minimal_headers():
    from drheader import Drheader

    scanner = Drheader(headers={"X-Content-Type-Options": "nosniff"})
    findings = scanner.analyze()
    assert isinstance(findings, list)
    assert len(findings) > 0, "Minimal headers should produce findings for missing headers"


check("Minimal headers produces findings", test_minimal_headers)


# ---------------------------------------------------------------------------
# 2. Online Python examples (Drheader with url=)
# ---------------------------------------------------------------------------
print("\n=== Online Python examples ===")


def test_scan_url():
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()
    assert isinstance(findings, list)


check(f"Scan {URL}", test_scan_url)


def test_filter_by_severity():
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()

    high = [f for f in findings if f.severity == "high"]
    medium = [f for f in findings if f.severity == "medium"]
    low = [f for f in findings if f.severity == "low"]

    assert len(high) + len(medium) + len(low) == len(findings), "Severity filter missed some findings"
    print(f"         -> High: {len(high)}, Medium: {len(medium)}, Low: {len(low)}")


check("Filter findings by severity", test_filter_by_severity)


def test_filter_by_header_name():
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()

    csp_issues = [f for f in findings if f.rule.startswith("Content-Security-Policy")]
    cookie_issues = [f for f in findings if f.rule.startswith("Set-Cookie")]
    assert isinstance(csp_issues, list)
    assert isinstance(cookie_issues, list)


check("Filter findings by header name", test_filter_by_header_name)


def test_owasp_preset_scan():
    from drheader import Drheader
    from drheader.utils import preset_rules

    rules = preset_rules("owasp-asvs-v14")
    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze(rules=rules)

    assert isinstance(findings, list)
    for f in findings:
        print(f"         -> [{f.severity.upper()}] {f.rule}: {f.message}")


check("OWASP ASVS V14 preset scan", test_owasp_preset_scan)


# ---------------------------------------------------------------------------
# 3. Finding field access
# ---------------------------------------------------------------------------
print("\n=== Finding field access ===")


def test_finding_fields():
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()
    assert len(findings) > 0, "Need at least one finding to verify fields"

    for f in findings:
        assert isinstance(f.rule, str) and f.rule
        assert isinstance(f.message, str) and f.message
        assert f.severity in ("high", "medium", "low")
        # Optional fields must be accessible (None or actual value)
        _ = f.value
        _ = f.expected
        _ = f.avoid
        _ = f.anomalies
        _ = f.delimiter


check("All documented Finding fields exist", test_finding_fields)


def test_finding_field_printing():
    """Mimics the 'Access Finding fields' snippet."""
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()
    assert len(findings) > 0

    f = findings[0]
    lines = []
    lines.append(f"Rule:     {f.rule}")
    lines.append(f"Message:  {f.message}")
    lines.append(f"Severity: {f.severity}")
    if f.value:
        lines.append(f"Value:    {f.value}")
    if f.expected:
        lines.append(f"Expected: {f.expected}")
    if f.avoid:
        lines.append(f"Avoid:    {f.avoid}")
    assert len(lines) >= 3


check("Finding field printing pattern", test_finding_field_printing)


# ---------------------------------------------------------------------------
# 4. to_dict()
# ---------------------------------------------------------------------------
print("\n=== to_dict() ===")


def test_to_dict():
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()
    assert len(findings) > 0

    # Single finding to dict
    finding_dict = findings[0].to_dict()
    assert isinstance(finding_dict, dict)
    assert "rule" in finding_dict
    assert "message" in finding_dict
    assert "severity" in finding_dict
    # None fields should be omitted
    for key, val in finding_dict.items():
        assert val is not None, f"to_dict() should omit None fields, but '{key}' is None"

    # All findings to list of dicts
    all_dicts = [f.to_dict() for f in findings]
    assert isinstance(all_dicts, list)
    assert len(all_dicts) == len(findings)


check("to_dict() basic behavior", test_to_dict)


def test_json_export():
    """Mimics the JSON export snippet."""
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()

    report = {
        "url": URL,
        "total": len(findings),
        "high": len([f for f in findings if f.severity == "high"]),
        "medium": len([f for f in findings if f.severity == "medium"]),
        "low": len([f for f in findings if f.severity == "low"]),
        "passed": len(findings) == 0,
        "findings": [f.to_dict() for f in findings],
    }

    json_str = json.dumps(report, indent=2)
    parsed = json.loads(json_str)
    assert parsed["url"] == URL
    assert isinstance(parsed["findings"], list)
    assert parsed["total"] == len(parsed["findings"])


check("JSON export for dashboards", test_json_export)


# ---------------------------------------------------------------------------
# 5. Rule loaders
# ---------------------------------------------------------------------------
print("\n=== Rule loaders ===")


def test_default_rules():
    from drheader.utils import default_rules

    rules = default_rules()
    assert isinstance(rules, dict)
    assert len(rules) > 0
    assert any(k.lower() == "content-security-policy" for k in rules)
    assert any(k.lower() == "strict-transport-security" for k in rules)


check("default_rules()", test_default_rules)


def test_preset_rules():
    from drheader.utils import preset_rules

    rules = preset_rules("owasp-asvs-v14")
    assert isinstance(rules, dict)
    assert len(rules) > 0


check("preset_rules('owasp-asvs-v14')", test_preset_rules)


def test_preset_rules_invalid():
    from drheader.utils import preset_rules

    try:
        preset_rules("nonexistent")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "nonexistent" in str(e)


check("preset_rules() rejects unknown preset", test_preset_rules_invalid)


def test_load_rules_from_file():
    from drheader.utils import load_rules

    yaml_content = textwrap.dedent("""\
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

        Strict-Transport-Security:
          Required: True
          Must-Contain:
            - includeSubDomains
            - preload
          Directives:
            max-age:
              Required: True
              Value-Gte: 31536000

        X-Internal-Debug:
          Required: False
          Severity: high
    """)

    rules = load_rules(rules_file=io.StringIO(yaml_content))
    assert isinstance(rules, dict)
    assert "Content-Security-Policy" in rules
    assert "Strict-Transport-Security" in rules
    assert "X-Internal-Debug" in rules


check("load_rules() from file (example YAML)", test_load_rules_from_file)


def test_load_rules_merge():
    from drheader.utils import load_rules

    yaml_content = textwrap.dedent("""\
        X-Custom-Header:
          Required: True
          Severity: medium
    """)

    rules = load_rules(rules_file=io.StringIO(yaml_content), merge_default=True)
    assert isinstance(rules, dict)
    assert "X-Custom-Header" in rules
    assert any(k.lower() == "content-security-policy" for k in rules)


check("load_rules() with merge_default=True", test_load_rules_merge)


# ---------------------------------------------------------------------------
# 6. Custom rules YAML — load and analyze
# ---------------------------------------------------------------------------
print("\n=== Custom rules YAML — load + analyze ===")


def test_custom_rules_analyze():
    from drheader import Drheader
    from drheader.utils import load_rules

    yaml_content = textwrap.dedent("""\
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

        Strict-Transport-Security:
          Required: True
          Must-Contain:
            - includeSubDomains
            - preload
          Directives:
            max-age:
              Required: True
              Value-Gte: 31536000

        X-Internal-Debug:
          Required: False
          Severity: high
    """)

    rules = load_rules(rules_file=io.StringIO(yaml_content))
    scanner = Drheader(headers={
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    })
    findings = scanner.analyze(rules=rules)
    assert isinstance(findings, list)
    debug_findings = [f for f in findings if "X-Internal-Debug" in f.rule]
    assert len(debug_findings) == 0, "X-Internal-Debug with Required: False should not trigger when absent"


check("Custom rules YAML analyze", test_custom_rules_analyze)


def test_custom_rules_from_tempfile():
    """Mimics 'load_rules(rules_file=open(...))' pattern from examples."""
    from drheader import Drheader
    from drheader.utils import load_rules

    yaml_content = textwrap.dedent("""\
        X-Content-Type-Options:
          Required: True
          Value: nosniff
          Severity: high
    """)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        f.flush()
        tmp_path = f.name

    try:
        rules = load_rules(rules_file=open(tmp_path))
        scanner = Drheader(headers={"X-Content-Type-Options": "nosniff"})
        findings = scanner.analyze(rules=rules)
        assert isinstance(findings, list)
        assert len(findings) == 0, "nosniff should pass"

        scanner2 = Drheader(headers={"X-Content-Type-Options": "wrong"})
        findings2 = scanner2.analyze(rules=load_rules(rules_file=open(tmp_path)))
        assert len(findings2) > 0, "Wrong value should produce findings"
    finally:
        Path(tmp_path).unlink()


check("Custom rules from temp file (open() pattern)", test_custom_rules_from_tempfile)


# ---------------------------------------------------------------------------
# 7. CLI examples
# ---------------------------------------------------------------------------
print("\n=== CLI examples ===")

# CLI uses --verify false to bypass local SSL cert issues
CLI_VERIFY = ["--verify", "false"]


def test_cli_scan_single():
    result = subprocess.run(
        ["uv", "run", "drheader", "scan", "single", URL] + CLI_VERIFY,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode in (0, 70), f"Unexpected exit code {result.returncode}: {result.stderr}"


check("CLI: drheader scan single", test_cli_scan_single)


def test_cli_scan_single_json():
    result = subprocess.run(
        ["uv", "run", "drheader", "scan", "single", "--output", "json", URL] + CLI_VERIFY,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode in (0, 70), f"Unexpected exit code {result.returncode}: {result.stderr}"
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)


check("CLI: drheader scan single --output json", test_cli_scan_single_json)


def test_cli_scan_single_preset():
    result = subprocess.run(
        ["uv", "run", "drheader", "scan", "single", "--preset", "owasp-asvs-v14", URL] + CLI_VERIFY,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode in (0, 70), f"Unexpected exit code {result.returncode}: {result.stderr}"


check("CLI: drheader scan single --preset owasp-asvs-v14", test_cli_scan_single_preset)


def test_cli_compare_single():
    headers = {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(headers, f)
        f.flush()
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["uv", "run", "drheader", "compare", "single", tmp_path],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 70), f"Unexpected exit code {result.returncode}: {result.stderr}"
    finally:
        Path(tmp_path).unlink()


check("CLI: drheader compare single <file>", test_cli_compare_single)


def test_cli_scan_single_rules_file_merge():
    yaml_content = textwrap.dedent("""\
        X-Content-Type-Options:
          Required: True
          Value: nosniff
          Severity: high
    """)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        f.flush()
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["uv", "run", "drheader", "scan", "single", "--rules-file", tmp_path, "--merge", URL] + CLI_VERIFY,
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 70), f"Unexpected exit code {result.returncode}: {result.stderr}"
    finally:
        Path(tmp_path).unlink()


check("CLI: drheader scan single --rules-file --merge", test_cli_scan_single_rules_file_merge)


def test_cli_json_output_to_file():
    """Mimics: drheader scan single --output json https://example.com > report.json"""
    result = subprocess.run(
        ["uv", "run", "drheader", "scan", "single", "--output", "json", URL] + CLI_VERIFY,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode in (0, 70)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(result.stdout)
        tmp_path = f.name
    try:
        with open(tmp_path) as f:
            data = json.load(f)
        assert isinstance(data, list)
    finally:
        Path(tmp_path).unlink()


check("CLI: JSON output > file pattern", test_cli_json_output_to_file)


# ---------------------------------------------------------------------------
# 8. Pre-deploy gate script pattern
# ---------------------------------------------------------------------------
print("\n=== Pre-deploy gate script pattern ===")


def test_predeploy_gate_pattern():
    from drheader import Drheader

    scanner = Drheader(url=URL, verify=False)
    findings = scanner.analyze()

    if not findings:
        status = f"PASS: {URL} — all security headers OK"
    else:
        high = [f for f in findings if f.severity == "high"]
        medium = [f for f in findings if f.severity == "medium"]
        status = f"SCAN: {URL} — {len(findings)} issues ({len(high)} high, {len(medium)} medium)"
        for f in findings:
            _ = f"  [{f.severity.upper()}] {f.rule}: {f.message}"

    assert isinstance(status, str)


check("Pre-deploy gate script pattern", test_predeploy_gate_pattern)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{'='*50}")
print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL} checks")
print(f"{'='*50}")

sys.exit(1 if FAIL else 0)
