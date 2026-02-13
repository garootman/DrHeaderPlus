#!/usr/bin/env python3

"""Tests for `utils.py` file."""

import os
import unittest

import responses
import yaml

from drheader import utils


class TestUtils(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "../test_resources/default_rules.yml")) as default_rules:
            self.default_rules = yaml.safe_load(default_rules.read())
        with open(os.path.join(os.path.dirname(__file__), "../test_resources/custom_rules.yml")) as custom_rules:
            self.custom_rules = yaml.safe_load(custom_rules.read())
        with open(
            os.path.join(os.path.dirname(__file__), "../test_resources/custom_rules_merged.yml")
        ) as custom_rules_merged:
            self.custom_rules_merged = yaml.safe_load(custom_rules_merged.read())

    def test_parse_policy__should_extract_standalone_directive(self):
        policy = "default-src 'none'; upgrade-insecure-requests"
        directives_list = utils.parse_policy(policy, ";", key_value_delimiter=" ", value_delimiter=" ")

        self.assertIn("upgrade-insecure-requests", directives_list)

    def test_parse_policy__should_extract_key_value_directive(self):
        policy = "default-src 'none'; upgrade-insecure-requests"
        directives_list = utils.parse_policy(policy, ";", key_value_delimiter=" ", value_delimiter=" ")

        expected = utils.KeyValueDirective("default-src", ["'none'"], "'none'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__should_extract_raw_key_value_directive(self):
        policy = "default-src 'none'; upgrade-insecure-requests"
        directives_list = utils.parse_policy(policy, ";", key_value_delimiter=" ", value_delimiter=" ")

        self.assertIn("default-src 'none'", directives_list)

    def test_parse_policy__should_extract_all_values_for_key_value_directive_with_multiple_values(self):
        policy = "default-src 'none'; script-src https: 'unsafe-inline'"
        directives_list = utils.parse_policy(policy, ";", key_value_delimiter=" ", value_delimiter=" ")

        expected = utils.KeyValueDirective("script-src", ["https:", "'unsafe-inline'"], "https: 'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__should_extract_keys_from_key_value_directives_when_keys_only_is_true(self):
        policy = "default-src 'none'"
        directives_list = utils.parse_policy(policy, ";", key_value_delimiter=" ", value_delimiter=" ", keys_only=True)

        self.assertIn("default-src", directives_list)

    def test_parse_policy__should_remove_strip_characters_from_directive_values(self):
        policy = "default-src 'none'; script-src 'unsafe-inline'"
        directives_list = utils.parse_policy(
            policy, ";", key_value_delimiter=" ", value_delimiter=" ", strip_chars="' "
        )

        expected = utils.KeyValueDirective("default-src", ["none"], "'none'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__should_handle_repeated_delimiters(self):
        policy = "default-src 'none';;  ;;   script-src   'self'   'unsafe-inline';;"
        directives_list = utils.parse_policy(policy, ";", " ", value_delimiter=" ")

        expected = utils.KeyValueDirective("script-src", ["'self'", "'unsafe-inline'"], "  'self'   'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_load_rules__merge_enabled__should_merge_custom_rules_with_default_rules(self):
        with open(os.path.join(os.path.dirname(__file__), "../test_resources/custom_rules.yml")) as custom_rules:
            response = utils.load_rules(rules_file=custom_rules, merge_default=True)

        self.assertEqual(response, self.custom_rules_merged)

    @responses.activate
    def test_load_rules__valid_rules_uri__should_load_rules_from_uri(self):
        uri = "http://localhost:8080/custom.yml"
        responses.add(responses.GET, uri, json=self.custom_rules, status=200)

        rules = utils.load_rules(rules_uri=uri)
        self.assertEqual(rules, self.custom_rules)

    @responses.activate
    def test_load_rules__no_content_from_uri__should_raise_an_error(self):
        uri = "http://mydomain.com/custom.yml"
        responses.add(responses.GET, uri, status=404)

        with self.assertRaises(Exception):
            utils.get_rules_from_uri(uri)


class TestPresetRules(unittest.TestCase):
    def test_presets_constant__should_contain_asvs_v14(self):
        self.assertIn("owasp-asvs-v14", utils.PRESETS)

    def test_preset_rules__should_load_asvs_v14_preset(self):
        rules = utils.preset_rules("owasp-asvs-v14")

        expected_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "X-Frame-Options",
            "Access-Control-Allow-Origin",
        ]
        for header in expected_headers:
            self.assertIn(header, rules, msg=f"{header} missing from ASVS preset")

    def test_preset_rules__should_not_contain_default_only_headers(self):
        rules = utils.preset_rules("owasp-asvs-v14")

        default_only_headers = [
            "Cache-Control",
            "Server",
            "Permissions-Policy",
            "X-Permitted-Cross-Domain-Policies",
            "X-XSS-Protection",
            "Pragma",
        ]
        for header in default_only_headers:
            self.assertNotIn(header, rules, msg=f"{header} should not be in ASVS preset")

    def test_preset_rules__unknown_preset_should_raise_value_error(self):
        with self.assertRaises(ValueError):
            utils.preset_rules("nonexistent-preset")
