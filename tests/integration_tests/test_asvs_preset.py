"""Integration tests for the OWASP ASVS V14 preset ruleset.

These tests run the full analysis pipeline (no mocks) against the ASVS preset
to verify that each mapped requirement is correctly enforced.
"""

import unittest

from drheader import Drheader
from drheader.report import Finding
from drheader.utils import preset_rules

_ASVS_RULES = preset_rules("owasp-asvs-v14")

# A fully ASVS-compliant header set
_COMPLIANT_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin",
    "X-Frame-Options": "DENY",
}


def _analyze(headers: dict) -> list[Finding]:
    return Drheader(headers=headers).analyze(rules=_ASVS_RULES)


class TestAvsvPresetCompliance(unittest.TestCase):
    """Verify that a fully compliant header set produces zero findings."""

    def test_fully_compliant_headers__should_produce_no_findings(self):
        report = _analyze(_COMPLIANT_HEADERS)
        self.assertEqual(len(report), 0, msg=f"Unexpected findings: {[f.to_dict() for f in report]}")


class TestAvsvPresetCsp(unittest.TestCase):
    """V14.4.3 — Content-Security-Policy."""

    def test_csp_missing__should_report_finding(self):
        headers = {k: v for k, v in _COMPLIANT_HEADERS.items() if k != "Content-Security-Policy"}
        report = _analyze(headers)

        expected = Finding(
            rule="Content-Security-Policy",
            message="Header not included in response",
            severity="high",
        )
        self.assertIn(expected, report)

    def test_csp_unsafe_inline__should_report_must_avoid(self):
        headers = {**_COMPLIANT_HEADERS, "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'"}
        report = _analyze(headers)

        csp_findings = [f for f in report if f.rule.startswith("Content-Security-Policy")]
        avoid_messages = [f for f in csp_findings if f.message == "Must-Avoid directive included"]
        self.assertTrue(len(avoid_messages) > 0, msg="Expected must-avoid finding for unsafe-inline")

    def test_csp_unsafe_eval__should_report_must_avoid(self):
        headers = {**_COMPLIANT_HEADERS, "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-eval'"}
        report = _analyze(headers)

        csp_findings = [f for f in report if f.rule.startswith("Content-Security-Policy")]
        avoid_messages = [f for f in csp_findings if f.message == "Must-Avoid directive included"]
        self.assertTrue(len(avoid_messages) > 0, msg="Expected must-avoid finding for unsafe-eval")

    def test_csp_default_src_wrong__should_report_value_error(self):
        headers = {**_COMPLIANT_HEADERS, "Content-Security-Policy": "default-src https://example.com"}
        report = _analyze(headers)

        expected = Finding(
            rule="Content-Security-Policy - default-src",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="high",
            value="https://example.com",
            expected=["none", "self"],
        )
        self.assertIn(expected, report)


class TestAvsvPresetXContentTypeOptions(unittest.TestCase):
    """V14.4.4 — X-Content-Type-Options."""

    def test_xcto_missing__should_report_finding(self):
        headers = {k: v for k, v in _COMPLIANT_HEADERS.items() if k != "X-Content-Type-Options"}
        report = _analyze(headers)

        expected = Finding(
            rule="X-Content-Type-Options",
            message="Header not included in response",
            severity="medium",
            expected=["nosniff"],
        )
        self.assertIn(expected, report)

    def test_xcto_wrong_value__should_report_finding(self):
        headers = {**_COMPLIANT_HEADERS, "X-Content-Type-Options": "nofollow"}
        report = _analyze(headers)

        expected = Finding(
            rule="X-Content-Type-Options",
            message="Value does not match security policy",
            severity="medium",
            value="nofollow",
            expected=["nosniff"],
        )
        self.assertIn(expected, report)


class TestAvsvPresetHsts(unittest.TestCase):
    """V14.4.5 — Strict-Transport-Security."""

    def test_hsts_missing__should_report_finding(self):
        headers = {k: v for k, v in _COMPLIANT_HEADERS.items() if k != "Strict-Transport-Security"}
        report = _analyze(headers)

        expected = Finding(
            rule="Strict-Transport-Security",
            message="Header not included in response",
            severity="high",
        )
        self.assertIn(expected, report)

    def test_hsts_without_includesubdomains__should_report_finding(self):
        headers = {**_COMPLIANT_HEADERS, "Strict-Transport-Security": "max-age=31536000"}
        report = _analyze(headers)

        expected = Finding(
            rule="Strict-Transport-Security",
            message="Must-Contain directive missed",
            severity="high",
            value="max-age=31536000",
            expected=["includeSubDomains"],
            anomalies=["includeSubDomains"],
        )
        self.assertIn(expected, report)

    def test_hsts_max_age_too_low__should_report_finding(self):
        headers = {**_COMPLIANT_HEADERS, "Strict-Transport-Security": "max-age=86400; includeSubDomains"}
        report = _analyze(headers)

        expected = Finding(
            rule="Strict-Transport-Security - max-age",
            message="Value does not meet minimum threshold",
            severity="high",
            value="86400",
            expected=["15724800"],
        )
        self.assertIn(expected, report)

    def test_hsts_max_age_exactly_at_threshold__should_pass(self):
        headers = {**_COMPLIANT_HEADERS, "Strict-Transport-Security": "max-age=15724800; includeSubDomains"}
        report = _analyze(headers)

        hsts_findings = [f for f in report if f.rule.startswith("Strict-Transport-Security")]
        self.assertEqual(len(hsts_findings), 0, msg=f"Unexpected HSTS findings: {hsts_findings}")


class TestAvsvPresetReferrerPolicy(unittest.TestCase):
    """V14.4.6 — Referrer-Policy."""

    def test_referrer_policy_missing__should_report_finding(self):
        headers = {k: v for k, v in _COMPLIANT_HEADERS.items() if k != "Referrer-Policy"}
        report = _analyze(headers)

        expected = Finding(
            rule="Referrer-Policy",
            message="Header not included in response",
            severity="medium",
            expected=["strict-origin", "strict-origin-when-cross-origin", "no-referrer"],
        )
        self.assertIn(expected, report)

    def test_referrer_policy_unsafe_url__should_report_finding(self):
        headers = {**_COMPLIANT_HEADERS, "Referrer-Policy": "unsafe-url"}
        report = _analyze(headers)

        expected = Finding(
            rule="Referrer-Policy",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="medium",
            value="unsafe-url",
            expected=["strict-origin", "strict-origin-when-cross-origin", "no-referrer"],
        )
        self.assertIn(expected, report)

    def test_referrer_policy_no_referrer__should_pass(self):
        headers = {**_COMPLIANT_HEADERS, "Referrer-Policy": "no-referrer"}
        report = _analyze(headers)

        rp_findings = [f for f in report if f.rule == "Referrer-Policy"]
        self.assertEqual(len(rp_findings), 0)


class TestAvsvPresetXFrameOptions(unittest.TestCase):
    """V14.4.7 — X-Frame-Options."""

    def test_xfo_missing__should_report_finding(self):
        headers = {k: v for k, v in _COMPLIANT_HEADERS.items() if k != "X-Frame-Options"}
        report = _analyze(headers)

        expected = Finding(
            rule="X-Frame-Options",
            message="Header not included in response",
            severity="medium",
            expected=["DENY", "SAMEORIGIN"],
        )
        self.assertIn(expected, report)

    def test_xfo_allow_from__should_report_finding(self):
        headers = {**_COMPLIANT_HEADERS, "X-Frame-Options": "ALLOW-FROM https://example.com"}
        report = _analyze(headers)

        expected = Finding(
            rule="X-Frame-Options",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="medium",
            value="ALLOW-FROM https://example.com",
            expected=["DENY", "SAMEORIGIN"],
        )
        self.assertIn(expected, report)

    def test_xfo_sameorigin__should_pass(self):
        headers = {**_COMPLIANT_HEADERS, "X-Frame-Options": "SAMEORIGIN"}
        report = _analyze(headers)

        xfo_findings = [f for f in report if f.rule == "X-Frame-Options"]
        self.assertEqual(len(xfo_findings), 0)


class TestAvsvPresetCors(unittest.TestCase):
    """V14.5.3 — Access-Control-Allow-Origin."""

    def test_cors_wildcard__should_report_must_avoid(self):
        headers = {**_COMPLIANT_HEADERS, "Access-Control-Allow-Origin": "*"}
        report = _analyze(headers)

        cors_findings = [f for f in report if f.rule == "Access-Control-Allow-Origin"]
        self.assertTrue(len(cors_findings) > 0, msg="Expected finding for ACAO wildcard")

    def test_cors_null__should_report_must_avoid(self):
        headers = {**_COMPLIANT_HEADERS, "Access-Control-Allow-Origin": "null"}
        report = _analyze(headers)

        cors_findings = [f for f in report if f.rule == "Access-Control-Allow-Origin"]
        self.assertTrue(len(cors_findings) > 0, msg="Expected finding for ACAO null")

    def test_cors_specific_origin__should_pass(self):
        headers = {**_COMPLIANT_HEADERS, "Access-Control-Allow-Origin": "https://example.com"}
        report = _analyze(headers)

        cors_findings = [f for f in report if f.rule == "Access-Control-Allow-Origin"]
        self.assertEqual(len(cors_findings), 0)

    def test_cors_absent__should_pass(self):
        """ACAO is optional in the ASVS preset — absence is fine."""
        report = _analyze(_COMPLIANT_HEADERS)

        cors_findings = [f for f in report if f.rule == "Access-Control-Allow-Origin"]
        self.assertEqual(len(cors_findings), 0)


class TestAvsvPresetExclusions(unittest.TestCase):
    """Headers NOT in the ASVS preset should not be flagged."""

    def test_missing_cache_control__should_not_be_flagged(self):
        report = _analyze(_COMPLIANT_HEADERS)

        cc_findings = [f for f in report if f.rule == "Cache-Control"]
        self.assertEqual(len(cc_findings), 0)

    def test_missing_permissions_policy__should_not_be_flagged(self):
        report = _analyze(_COMPLIANT_HEADERS)

        pp_findings = [f for f in report if f.rule == "Permissions-Policy"]
        self.assertEqual(len(pp_findings), 0)

    def test_missing_x_xss_protection__should_not_be_flagged(self):
        report = _analyze(_COMPLIANT_HEADERS)

        xxp_findings = [f for f in report if f.rule == "X-XSS-Protection"]
        self.assertEqual(len(xxp_findings), 0)
