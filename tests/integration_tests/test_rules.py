import unittest

from drheader.report import Finding
from tests.integration_tests import utils


class TestDefaultRules(unittest.TestCase):
    def tearDown(self):
        utils.reset_default_rules()

    def test__should_validate_all_rules_for_valid_headers(self):
        headers = utils.get_headers()

        report = utils.process_test(headers=headers)
        self.assertEqual(len(report), 0, msg=utils.build_error_message(report))

    def test_cache_control__should_exist(self):
        headers = utils.delete_headers("Cache-Control")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Cache-Control",
            message="Header not included in response",
            severity="high",
            expected=["no-store", "max-age=0"],
            delimiter=",",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cache-Control"))

    def test_cache_control__should_disable_caching(self):
        headers = utils.add_or_modify_header("Cache-Control", "no-cache")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Cache-Control",
            message="Value does not match security policy",
            severity="high",
            value="no-cache",
            expected=["no-store", "max-age=0"],
            delimiter=",",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cache-Control"))

    def test_csp__should_exist(self):
        headers = utils.delete_headers("Content-Security-Policy")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy",
            message="Header not included in response",
            severity="high",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp__should_enforce_default_src(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src https://example.com")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - default-src",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="high",
            value="https://example.com",
            expected=["none", "self"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp__should_avoid_data_scheme(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; img-src data:")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - img-src",
            message="Must-Avoid directive included",
            severity="high",
            value="data:",
            avoid=["unsafe-inline", "unsafe-eval", "data:", "http:", "ftp:"],
            anomalies=["data:"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp__should_avoid_http_scheme(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; img-src http:")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - img-src",
            message="Must-Avoid directive included",
            severity="high",
            value="http:",
            avoid=["unsafe-inline", "unsafe-eval", "data:", "http:", "ftp:"],
            anomalies=["http:"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_script_src__should_avoid_unsafe_inline(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'"
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [item for item in report if item.rule == "Content-Security-Policy - script-src"]
        anomalies = []
        for item in csp_script_violations:
            anomalies.extend(item.anomalies or [])
        self.assertIn("unsafe-inline", anomalies)

    def test_csp_script_src__should_avoid_data_scheme(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; script-src 'self' data:")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - script-src",
            message="Must-Avoid directive included",
            severity="high",
            value="'self' data:",
            avoid=["unsafe-inline", "unsafe-eval", "data:", "http:", "https:", "*"],
            anomalies=["data:"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_script_src__should_avoid_https_scheme(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; script-src https:")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - script-src",
            message="Must-Avoid directive included",
            severity="high",
            value="https:",
            avoid=["unsafe-inline", "unsafe-eval", "data:", "http:", "https:", "*"],
            anomalies=["https:"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_script_src__should_avoid_wildcard(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; script-src *")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - script-src",
            message="Must-Avoid directive included",
            severity="high",
            value="*",
            avoid=["unsafe-inline", "unsafe-eval", "data:", "http:", "https:", "*"],
            anomalies=["*"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_script_src__should_pass_with_safe_values(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; script-src 'self'")

        report = utils.process_test(headers=headers)
        csp_script_violations = [item for item in report if item.rule == "Content-Security-Policy - script-src"]
        self.assertEqual(len(csp_script_violations), 0, msg=utils.build_error_message(report))

    def test_csp_script_src__nonce_should_neutralize_unsafe_inline(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'nonce-abc123' 'unsafe-inline'",
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - script-src" and "unsafe-inline" in (item.anomalies or [])
        ]
        self.assertEqual(len(csp_script_violations), 0, msg=utils.build_error_message(report))

    def test_csp_script_src__hash_should_neutralize_unsafe_inline(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'sha256-abc123' 'unsafe-inline'",
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - script-src" and "unsafe-inline" in (item.anomalies or [])
        ]
        self.assertEqual(len(csp_script_violations), 0, msg=utils.build_error_message(report))

    def test_csp_script_src__nonce_should_not_neutralize_unsafe_eval(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'nonce-abc123' 'unsafe-eval'",
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - script-src" and "unsafe-eval" in (item.anomalies or [])
        ]
        self.assertGreater(len(csp_script_violations), 0, msg=utils.build_error_message(report))

    def test_csp_style_src__nonce_should_neutralize_unsafe_inline(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'nonce-xyz789' 'unsafe-inline'",
        )

        report = utils.process_test(headers=headers)
        csp_style_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - style-src" and "unsafe-inline" in (item.anomalies or [])
        ]
        self.assertEqual(len(csp_style_violations), 0, msg=utils.build_error_message(report))

    def test_csp_top_level__nonce_in_script_src_should_neutralize_unsafe_inline(self):
        """Top-level must-avoid should not flag unsafe-inline in script-src when nonces are present."""
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'nonce-abc123' 'unsafe-inline'",
        )

        report = utils.process_test(headers=headers)
        # The top-level CSP must-avoid should not flag unsafe-inline for the script-src directive
        csp_top_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy" and "unsafe-inline" in (item.anomalies or [])
        ]
        self.assertEqual(len(csp_top_violations), 0, msg=utils.build_error_message(report))

    def test_csp_script_src__strict_dynamic_with_nonce_should_ignore_scheme_sources(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic' https: 'unsafe-inline'",
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [item for item in report if item.rule == "Content-Security-Policy - script-src"]
        # https: and unsafe-inline should both be suppressed (strict-dynamic ignores schemes, nonce neutralizes inline)
        for violation in csp_script_violations:
            for suppressed in ["https:", "unsafe-inline"]:
                self.assertNotIn(suppressed, violation.anomalies or [], msg=utils.build_error_message(report))

    def test_csp_script_src__strict_dynamic_without_nonce_should_still_flag(self):
        """strict-dynamic alone without nonces does not suppress anything."""
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'strict-dynamic' https:",
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - script-src" and "https:" in (item.anomalies or [])
        ]
        self.assertGreater(len(csp_script_violations), 0, msg=utils.build_error_message(report))

    def test_csp_script_src__strict_dynamic_should_not_suppress_unsafe_eval(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic' 'unsafe-eval'",
        )

        report = utils.process_test(headers=headers)
        csp_script_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - script-src" and "unsafe-eval" in (item.anomalies or [])
        ]
        self.assertGreater(len(csp_script_violations), 0, msg=utils.build_error_message(report))

    def test_csp_top_level__strict_dynamic_with_nonce_should_suppress_scheme_in_script_src(self):
        """Top-level must-avoid should not flag http:/https: in script-src when strict-dynamic + nonce are present."""
        headers = utils.add_or_modify_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic' http:",
        )

        report = utils.process_test(headers=headers)
        csp_top_violations = [
            item for item in report if item.rule == "Content-Security-Policy" and "http:" in (item.anomalies or [])
        ]
        csp_directive_violations = [
            item
            for item in report
            if item.rule == "Content-Security-Policy - script-src" and "http:" in (item.anomalies or [])
        ]
        self.assertEqual(len(csp_top_violations), 0, msg=utils.build_error_message(report))
        self.assertEqual(len(csp_directive_violations), 0, msg=utils.build_error_message(report))

    def test_csp_report_only__without_enforcing_csp_should_fail(self):
        headers = utils.delete_headers("Content-Security-Policy")
        headers["Content-Security-Policy-Report-Only"] = "default-src 'none'"

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy-Report-Only",
            message="Content-Security-Policy-Report-Only is set without an enforcing Content-Security-Policy header",
            severity="high",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_report_only__with_enforcing_csp_should_not_flag(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'")
        headers["Content-Security-Policy-Report-Only"] = "default-src 'none'"

        report = utils.process_test(headers=headers)
        report_only_violations = [item for item in report if item.rule == "Content-Security-Policy-Report-Only"]
        self.assertEqual(len(report_only_violations), 0, msg=utils.build_error_message(report))

    def test_csp_style_src__should_avoid_data_scheme(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; style-src data:")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - style-src",
            message="Must-Avoid directive included",
            severity="high",
            value="data:",
            avoid=["unsafe-eval", "data:"],
            anomalies=["data:"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_object_src__should_avoid_wildcard(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; object-src *")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - object-src",
            message="Must-Avoid directive included",
            severity="high",
            value="*",
            avoid=["*", "http:", "https:", "data:"],
            anomalies=["*"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_form_action__should_enforce_safe_values(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy", "default-src 'none'; form-action https://evil.com"
        )

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - form-action",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="high",
            value="https://evil.com",
            expected=["none", "self"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_form_action__should_pass_with_self(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; form-action 'self'")

        report = utils.process_test(headers=headers)
        form_violations = [item for item in report if item.rule == "Content-Security-Policy - form-action"]
        self.assertEqual(len(form_violations), 0, msg=utils.build_error_message(report))

    def test_csp_base_uri__should_enforce_safe_values(self):
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'; base-uri https://evil.com")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - base-uri",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="high",
            value="https://evil.com",
            expected=["none", "self"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_frame_ancestors__should_enforce_safe_values(self):
        headers = utils.add_or_modify_header(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors https://evil.com"
        )

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Content-Security-Policy - frame-ancestors",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="high",
            value="https://evil.com",
            expected=["none", "self"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Content-Security-Policy"))

    def test_csp_directives__should_not_validate_when_absent(self):
        """Optional directives should not produce violations when not present in CSP."""
        headers = utils.add_or_modify_header("Content-Security-Policy", "default-src 'none'")

        report = utils.process_test(headers=headers)
        directive_violations = [
            item
            for item in report
            if item.rule.startswith("Content-Security-Policy -")
            and item.rule != "Content-Security-Policy - default-src"
        ]
        self.assertEqual(len(directive_violations), 0, msg=utils.build_error_message(report))

    def test_acao__should_avoid_wildcard(self):
        headers = utils.add_or_modify_header("Access-Control-Allow-Origin", "*")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Access-Control-Allow-Origin",
            message="Must-Avoid directive included",
            severity="high",
            value="*",
            avoid=["*"],
            anomalies=["*"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Access-Control-Allow-Origin"))

    def test_acao__should_not_flag_specific_origin(self):
        headers = utils.add_or_modify_header("Access-Control-Allow-Origin", "https://example.com")

        report = utils.process_test(headers=headers)
        acao_violations = [item for item in report if item.rule == "Access-Control-Allow-Origin"]
        self.assertEqual(len(acao_violations), 0, msg=utils.build_error_message(report))

    def test_acao__should_not_require_presence(self):
        headers = utils.get_headers()  # No ACAO header present

        report = utils.process_test(headers=headers)
        acao_violations = [item for item in report if item.rule == "Access-Control-Allow-Origin"]
        self.assertEqual(len(acao_violations), 0, msg=utils.build_error_message(report))

    def test_coep__should_exist_when_cross_origin_isolated_is_true(self):
        headers = utils.delete_headers("Cross-Origin-Embedder-Policy")

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = Finding(
            rule="Cross-Origin-Embedder-Policy",
            message="Header not included in response",
            severity="high",
            expected=["require-corp"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cross-Origin-Embedder-Policy"))

    def test_coep__should_enforce_require_corp_when_cross_origin_isolated_is_true(self):
        headers = utils.add_or_modify_header("Cross-Origin-Embedder-Policy", "unsafe-none")

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = Finding(
            rule="Cross-Origin-Embedder-Policy",
            message="Value does not match security policy",
            severity="high",
            value="unsafe-none",
            expected=["require-corp"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cross-Origin-Embedder-Policy"))

    def test_coop__should_exist_when_cross_origin_isolated_is_true(self):
        headers = utils.delete_headers("Cross-Origin-Opener-Policy")

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = Finding(
            rule="Cross-Origin-Opener-Policy",
            message="Header not included in response",
            severity="high",
            expected=["same-origin"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cross-Origin-Opener-Policy"))

    def test_coop__should_enforce_same_origin_when_cross_origin_isolated_is_true(self):
        headers = utils.add_or_modify_header("Cross-Origin-Opener-Policy", "same-origin-allow-popups")

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = Finding(
            rule="Cross-Origin-Opener-Policy",
            message="Value does not match security policy",
            severity="high",
            value="same-origin-allow-popups",
            expected=["same-origin"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cross-Origin-Opener-Policy"))

    def test_cross_origin_resource_policy__should_exist(self):
        headers = utils.delete_headers("Cross-Origin-Resource-Policy")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Cross-Origin-Resource-Policy",
            message="Header not included in response",
            severity="medium",
            expected=["same-origin"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cross-Origin-Resource-Policy"))

    def test_cross_origin_resource_policy__should_enforce_same_origin(self):
        headers = utils.add_or_modify_header("Cross-Origin-Resource-Policy", "cross-origin")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Cross-Origin-Resource-Policy",
            message="Value does not match security policy",
            severity="medium",
            value="cross-origin",
            expected=["same-origin"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Cross-Origin-Resource-Policy"))

    def test_permissions_policy__should_exist(self):
        headers = utils.delete_headers("Permissions-Policy")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Permissions-Policy",
            message="Header not included in response",
            severity="medium",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Permissions-Policy"))

    def test_pragma__should_validate_when_present(self):
        headers = utils.add_or_modify_header("Pragma", "public")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Pragma",
            message="Value does not match security policy",
            severity="low",
            value="public",
            expected=["no-cache"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Pragma"))

    def test_pragma__should_not_require_presence(self):
        headers = utils.delete_headers("Pragma")

        report = utils.process_test(headers=headers)
        pragma_violations = [item for item in report if item.rule == "Pragma"]
        self.assertEqual(len(pragma_violations), 0, msg=utils.build_error_message(report))

    def test_referrer_policy__should_exist(self):
        headers = utils.delete_headers("Referrer-Policy")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Referrer-Policy",
            message="Header not included in response",
            severity="medium",
            expected=["strict-origin", "strict-origin-when-cross-origin", "no-referrer"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Referrer-Policy"))

    def test_referrer_policy__should_enforce_strict_policy(self):
        headers = utils.add_or_modify_header("Referrer-Policy", "same-origin")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Referrer-Policy",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="medium",
            value="same-origin",
            expected=["strict-origin", "strict-origin-when-cross-origin", "no-referrer"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Referrer-Policy"))

    def test_server__should_not_exist(self):
        headers = utils.add_or_modify_header("Server", "Apache/2.4.1 (Unix)")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Server",
            message="Header should not be returned",
            severity="medium",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Server"))

    def test_set_cookie__should_enforce_secure_for_all_cookies(self):
        headers = utils.add_or_modify_header("Set-Cookie", ["session_id=585733723; HttpOnly; SameSite=Strict"])

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Set-Cookie - session_id",
            message="Must-Contain directive missed",
            severity="high",
            value="585733723; HttpOnly; SameSite=Strict",
            expected=["HttpOnly", "Secure", "SameSite"],
            delimiter=";",
            anomalies=["Secure"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Set-Cookie"))

    def test_set_cookie__should_enforce_httponly_for_all_cookies(self):
        headers = utils.add_or_modify_header("Set-Cookie", ["session_id=585733723; Secure; SameSite=Strict"])

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Set-Cookie - session_id",
            message="Must-Contain directive missed",
            severity="high",
            value="585733723; Secure; SameSite=Strict",
            expected=["HttpOnly", "Secure", "SameSite"],
            delimiter=";",
            anomalies=["HttpOnly"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Set-Cookie"))

    def test_set_cookie__should_enforce_samesite_for_all_cookies(self):
        headers = utils.add_or_modify_header("Set-Cookie", ["session_id=585733723; HttpOnly; Secure"])

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Set-Cookie - session_id",
            message="Must-Contain directive missed",
            severity="high",
            value="585733723; HttpOnly; Secure",
            expected=["HttpOnly", "Secure", "SameSite"],
            delimiter=";",
            anomalies=["SameSite"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Set-Cookie"))

    def test_set_cookie__samesite_none_without_secure_should_fail(self):
        headers = utils.add_or_modify_header("Set-Cookie", ["session_id=abc; HttpOnly; SameSite=None"])

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Set-Cookie - session_id",
            message="SameSite=None requires Secure flag",
            severity="high",
            value="session_id=abc; HttpOnly; SameSite=None",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Set-Cookie"))

    def test_set_cookie__samesite_none_with_secure_should_pass(self):
        headers = utils.add_or_modify_header("Set-Cookie", ["session_id=abc; HttpOnly; Secure; SameSite=None"])

        report = utils.process_test(headers=headers)
        for finding in report:
            self.assertNotEqual(
                finding.message,
                "SameSite=None requires Secure flag",
                msg=utils.build_error_message(report, rule="Set-Cookie"),
            )

    def test_set_cookie__samesite_lax_without_secure_should_not_flag_samesite_issue(self):
        headers = utils.add_or_modify_header("Set-Cookie", ["session_id=abc; HttpOnly; SameSite=Lax"])

        report = utils.process_test(headers=headers)
        for finding in report:
            self.assertNotEqual(
                finding.message,
                "SameSite=None requires Secure flag",
                msg=utils.build_error_message(report, rule="Set-Cookie"),
            )

    def test_strict_transport_security__should_exist(self):
        headers = utils.delete_headers("Strict-Transport-Security")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Strict-Transport-Security",
            message="Header not included in response",
            severity="high",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Strict-Transport-Security"))

    def test_strict_transport_security__max_age_below_threshold_should_fail(self):
        headers = utils.add_or_modify_header("Strict-Transport-Security", "max-age=7776000; includeSubDomains")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Strict-Transport-Security - max-age",
            message="Value does not meet minimum threshold",
            severity="high",
            value="7776000",
            expected=["15552000"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Strict-Transport-Security"))

    def test_strict_transport_security__max_age_at_threshold_should_pass(self):
        headers = utils.add_or_modify_header("Strict-Transport-Security", "max-age=15552000; includeSubDomains")

        report = utils.process_test(headers=headers)
        for finding in report:
            self.assertFalse(
                finding.rule.startswith("Strict-Transport-Security"),
                msg=utils.build_error_message(report, rule="Strict-Transport-Security"),
            )

    def test_strict_transport_security__max_age_above_threshold_should_pass(self):
        headers = utils.add_or_modify_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

        report = utils.process_test(headers=headers)
        for finding in report:
            self.assertFalse(
                finding.rule.startswith("Strict-Transport-Security"),
                msg=utils.build_error_message(report, rule="Strict-Transport-Security"),
            )

    def test_strict_transport_security__missing_include_subdomains_should_fail(self):
        headers = utils.add_or_modify_header("Strict-Transport-Security", "max-age=31536000")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Strict-Transport-Security",
            message="Must-Contain directive missed",
            severity="high",
            value="max-age=31536000",
            expected=["includeSubDomains"],
            anomalies=["includeSubDomains"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Strict-Transport-Security"))

    def test_strict_transport_security__missing_max_age_directive_should_fail(self):
        headers = utils.add_or_modify_header("Strict-Transport-Security", "includeSubDomains")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="Strict-Transport-Security - max-age",
            message="Directive not included in response",
            severity="high",
            expected=["15552000"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "Strict-Transport-Security"))

    def test_user_agent__should_not_exist(self):
        headers = utils.add_or_modify_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus Player)")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="User-Agent",
            message="Header should not be returned",
            severity="low",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "User-Agent"))

    def test_x_aspnet_version__should_not_exist(self):
        headers = utils.add_or_modify_header("X-AspNet-Version", "2.0.50727")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-AspNet-Version",
            message="Header should not be returned",
            severity="medium",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-AspNet-Version"))

    def test_x_client_ip__should_not_exist(self):
        headers = utils.add_or_modify_header("X-Client-IP", "27.59.32.182")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Client-IP",
            message="Header should not be returned",
            severity="medium",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Client-IP"))

    def test_x_content_type_options__should_exist(self):
        headers = utils.delete_headers("X-Content-Type-Options")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Content-Type-Options",
            message="Header not included in response",
            severity="medium",
            expected=["nosniff"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Content-Type-Options"))

    def test_x_frame_options__should_exist(self):
        headers = utils.delete_headers("X-Frame-Options")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Frame-Options",
            message="Header not included in response",
            severity="medium",
            expected=["DENY", "SAMEORIGIN"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Frame-Options"))

    def test_x_frame_options__should_disable_allow_from(self):
        headers = utils.add_or_modify_header("X-Frame-Options", "ALLOW-FROM https//example.com")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Frame-Options",
            message="Value does not match security policy. Exactly one of the expected items was expected",
            severity="medium",
            value="ALLOW-FROM https//example.com",
            expected=["DENY", "SAMEORIGIN"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Frame-Options"))

    def test_x_forwarded_for__should_not_exist(self):
        headers = utils.add_or_modify_header("X-Forwarded-For", "2001:db8:85a3:8d3:1319:8a2e:370:7348")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Forwarded-For",
            message="Header should not be returned",
            severity="medium",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Forwarded-For"))

    def test_x_generator__should_not_exist(self):
        headers = utils.add_or_modify_header("X-Generator", "Drupal 7 (http://drupal.org)")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Generator",
            message="Header should not be returned",
            severity="low",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Generator"))

    def test_x_permitted_cross_domain_policies__should_exist(self):
        headers = utils.delete_headers("X-Permitted-Cross-Domain-Policies")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Permitted-Cross-Domain-Policies",
            message="Header not included in response",
            severity="low",
            expected=["none"],
        )
        self.assertIn(
            expected, report, msg=utils.build_error_message(report, expected, "X-Permitted-Cross-Domain-Policies")
        )

    def test_x_permitted_cross_domain_policies__should_enforce_none(self):
        headers = utils.add_or_modify_header("X-Permitted-Cross-Domain-Policies", "all")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Permitted-Cross-Domain-Policies",
            message="Value does not match security policy",
            severity="low",
            value="all",
            expected=["none"],
        )
        self.assertIn(
            expected, report, msg=utils.build_error_message(report, expected, "X-Permitted-Cross-Domain-Policies")
        )

    def test_x_powered_by__should_not_exist(self):
        headers = utils.add_or_modify_header("X-Powered-By", "ASP.NET")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-Powered-By",
            message="Header should not be returned",
            severity="medium",
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-Powered-By"))

    def test_x_xss_protection__should_exist(self):
        headers = utils.delete_headers("X-XSS-Protection")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-XSS-Protection",
            message="Header not included in response",
            severity="low",
            expected=["0"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-XSS-Protection"))

    def test_x_xss_protection__should_disable_filter(self):
        headers = utils.add_or_modify_header("X-XSS-Protection", "1; mode=block")

        report = utils.process_test(headers=headers)
        expected = Finding(
            rule="X-XSS-Protection",
            message="Value does not match security policy",
            severity="low",
            value="1; mode=block",
            expected=["0"],
        )
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, "X-XSS-Protection"))
