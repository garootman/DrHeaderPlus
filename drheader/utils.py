"""Utility functions for core module."""

import io
import os
from typing import IO, Any, NamedTuple

import requests
import yaml


class KeyValueDirective(NamedTuple):
    key: str
    value: list[str]
    raw_value: str | None = None


def default_rules() -> dict[str, Any]:
    """Returns the drHEADer default ruleset."""
    with open(os.path.join(os.path.dirname(__file__), "resources/rules.yml")) as rules:
        rules = yaml.safe_load(rules.read())
        return rules


def load_rules(
    rules_file: IO[Any] | None = None,
    rules_uri: str | None = None,
    merge_default: bool = False,
) -> dict[str, Any]:
    """Returns a drHEADer ruleset from a file.

    The loaded ruleset can be configured to be merged with the default drHEADer rules. If a rule exists in both the
    custom rules and default rules, the custom one will take priority and override the default one. Otherwise, the new
    custom rule will be appended to the default rules. If no file is provided, the default rules will be returned.

    Args:
        rules_file (file): (optional) The YAML file containing the ruleset.
        rules_uri (str): (optional) The YAML file containing the ruleset.
        merge_default (bool): (optional) Merge the custom ruleset with the drHEADer default ruleset. Default is False.

    Returns:
        A dict containing the loaded rules.
    """
    if not rules_file:
        if not rules_uri:
            raise ValueError("No resource provided. Either 'rules_file' or 'rules_uri' must be defined.")
        else:
            rules_file = get_rules_from_uri(rules_uri)

    rules = yaml.safe_load(rules_file.read())
    return _merge_with_default_rules(rules) if merge_default else rules


def parse_policy(
    policy: str,
    item_delimiter: str | None = None,
    key_value_delimiter: str | None = None,
    value_delimiter: str | None = None,
    strip_chars: str | None = None,
    keys_only: bool = False,
) -> list[str | KeyValueDirective]:  # noqa: E501
    """Parses a policy string into a list of individual directives.

    Args:
        policy (str): The policy to be parsed.
        item_delimiter (str): (optional) The character that delimits individual directives.
        key_value_delimiter (str): (optional) The character that delimits keys and values in key-value directives.
        value_delimiter (str): (optional) The character that delimits individual values in key-value directives.
        strip_chars (str): (optional) A string of characters to strip from directive values.
        keys_only (bool): (optional) A flag to return only keys from key-value directives. Default is False.

    Returns:
        A list of directives.
    """
    if not item_delimiter:
        return [policy.strip(strip_chars)]
    if not key_value_delimiter:
        return [item.strip(strip_chars) for item in policy.strip().split(item_delimiter)]

    directives = []
    for item in policy.strip().split(item_delimiter):
        directives.append(item.strip())
        split_item = item.strip(key_value_delimiter).split(key_value_delimiter, 1)
        if len(split_item) == 2:
            if keys_only:
                directives.append(split_item[0].strip())
            else:
                key_value_directive = _extract_key_value_directive(split_item, value_delimiter, strip_chars)
                directives.append(key_value_directive)
    return directives


def get_rules_from_uri(uri: str) -> io.BytesIO:
    response = requests.get(uri, timeout=5)
    response.raise_for_status()
    return io.BytesIO(response.content)


def _merge_with_default_rules(rules: dict[str, Any]) -> dict[str, Any]:
    merged_ruleset = default_rules()
    for rule in rules:
        merged_ruleset[rule] = rules[rule]
    return merged_ruleset


def _extract_key_value_directive(
    directive: list[str],
    value_delimiter: str | None,
    strip_chars: str | None,
) -> KeyValueDirective:
    if value_delimiter:
        value_items = list(filter(lambda s: s.strip(), directive[1].split(value_delimiter)))
        value = [item.strip(strip_chars) for item in value_items]
    else:
        value = [directive[1].strip(strip_chars)]
    return KeyValueDirective(directive[0].strip(), value, directive[1])
