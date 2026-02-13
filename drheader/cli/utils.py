"""Utility functions for cli module."""

import os
from typing import IO, Any

import tabulate
from junitparser import Failure, JUnitXml, TestCase, TestSuite

from drheader import utils


def get_rules(
    rules_file: IO[Any] | None = None, rules_uri: str | None = None, merge_default: bool = False,
) -> dict[str, Any]:
    if rules_file or rules_uri:
        return utils.load_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge_default)
    else:
        return utils.default_rules()


def tabulate_report(report: list[dict[str, Any]]) -> str:
    rows = []
    final_string = ''

    for validation_error in report:
        values = [[k, v] for k, v in validation_error.items()]
        rows.append(values)
    for validation_error in rows:
        final_string += '----\n'
        final_string += tabulate.tabulate(validation_error, tablefmt='presto') + '\n'

    return final_string


def file_junit_report(rules: dict[str, Any], report: list[dict[str, Any]]) -> None:
    """Generates a JUnit XML report from a scan result.

    Args:
        rules (dict): The rules used to perform the scan.
        report (list): The report generated from the scan.
    """
    test_suite = TestSuite('drHEADer')

    for header in rules:
        test_case = None
        for validation_error in report:
            if (title := validation_error.get('rule')).startswith(header):
                validation_error = {k: v for k, v in validation_error.items() if k != 'rule'}
                test_case = TestCase(title)
                failure = Failure(message=validation_error.pop('message'))
                failure.text = str(validation_error)
                test_case.result = [failure]
                test_suite.add_testcase(test_case)
        if not test_case:
            test_case = TestCase(header)
            test_suite.add_testcase(test_case)

    os.makedirs('reports', exist_ok=True)
    xml = JUnitXml()
    xml.add_testsuite(test_suite)
    xml.write('reports/junit.xml')
