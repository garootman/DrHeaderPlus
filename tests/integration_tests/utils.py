import json
import os
from typing import Any

from drheader import utils as drheader_utils
from drheader.core import Drheader
from drheader.report import Finding


def get_headers():
    with open(os.path.join(os.path.dirname(__file__), "../test_resources/headers_ok.json")) as headers:
        return json.load(headers)


def add_or_modify_header(header_name, update_value):
    headers = get_headers()
    headers[header_name] = update_value
    return headers


def delete_headers(*args):
    headers = get_headers()
    for header_name in args:
        headers.pop(header_name, None)
    return headers


def process_test(
    headers=None,
    url=None,
    rules: dict[str, Any] | None = None,
    cross_origin_isolated=False,
):
    if rules is None:
        rules = drheader_utils.default_rules()

    drheader = Drheader(headers=headers, url=url)
    return drheader.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)


def build_error_message(report: list[Finding], expected: Finding | None = None, rule: str | None = None) -> str:
    unexpected_items = []
    for item in report:
        if item != expected:
            if rule and item.rule.startswith(rule):
                unexpected_items.append(item)
            elif not rule:
                unexpected_items.append(item)

    error_message = "\n"
    if len(unexpected_items) > 0:
        error_message += "\nThe following items were found but were not expected in the report:\n"
        error_message += json.dumps([i.to_dict() for i in unexpected_items], indent=2)
    if expected and expected not in report:
        error_message += "\n\nThe following was not found but was expected in the report:\n"
        error_message += json.dumps(expected.to_dict(), indent=2)
    return error_message
