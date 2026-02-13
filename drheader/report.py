"""Primary module for report generation and storage."""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ErrorType(Enum):
    AVOID = "Must-Avoid directive included"
    CONTAIN = "Must-Contain directive missed"
    CONTAIN_ONE = "Must-Contain-One directive missed. At least one of the expected items was expected"
    CORS_ORIGIN_REFLECTED = "Access-Control-Allow-Origin reflects arbitrary Origin (potential CORS misconfiguration)"
    DISALLOWED = "{} should not be returned"
    REPORT_ONLY_NO_ENFORCING = (
        "Content-Security-Policy-Report-Only is set without an enforcing Content-Security-Policy header"
    )
    REQUIRED = "{} not included in response"
    SAMESITE_NONE_NO_SECURE = "SameSite=None requires Secure flag"
    VALUE = "Value does not match security policy"
    VALUE_ANY = "Value does not match security policy. At least one of the expected items was expected"
    VALUE_GTE = "Value does not meet minimum threshold"
    VALUE_ONE = "Value does not match security policy. Exactly one of the expected items was expected"


@dataclass
class ReportItem:
    severity: str
    error_type: ErrorType
    header: str
    directive: str | None = None
    cookie: str | None = None
    value: str | None = None
    avoid: list[str] | None = None
    expected: list[str] | None = None
    anomalies: list[str] | None = None
    delimiter: str | None = None


@dataclass
class Finding:
    rule: str
    message: str
    severity: str
    value: str | None = None
    expected: list[str] | None = None
    avoid: list[str] | None = None
    anomalies: list[str] | None = None
    delimiter: str | None = None

    @classmethod
    def from_report_item(cls, item: ReportItem) -> "Finding":
        """Create a Finding from a ReportItem."""
        if item.directive:
            rule = f"{item.header} - {item.directive}"
            message = item.error_type.value.format("Directive")
        elif item.cookie:
            rule = f"{item.header} - {item.cookie}"
            message = item.error_type.value.format("Cookie")
        else:
            rule = item.header
            message = item.error_type.value.format("Header")

        delimiter = item.delimiter if item.expected and len(item.expected) > 1 and item.delimiter else None

        return cls(
            rule=rule,
            message=message,
            severity=item.severity,
            value=item.value if item.value else None,
            expected=item.expected if item.expected else None,
            avoid=item.avoid if item.avoid else None,
            anomalies=item.anomalies if item.anomalies else None,
            delimiter=delimiter,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict, omitting None fields (preserves current behavior)."""
        d: dict[str, Any] = {"rule": self.rule, "message": self.message, "severity": self.severity}
        if self.value is not None:
            d["value"] = self.value
        if self.expected is not None:
            d["expected"] = self.expected
            if len(self.expected) > 1 and self.delimiter is not None:
                d["delimiter"] = self.delimiter
        elif self.avoid is not None:
            d["avoid"] = self.avoid
        if self.anomalies is not None:
            d["anomalies"] = self.anomalies
        return d


class Reporter:
    """Class to generate and store reports from a scan.

    Attributes:
        report (list): The report detailing validation failures encountered during a scan.
    """

    def __init__(self) -> None:
        """Initialises a Reporter instance with an empty report."""
        self.report: list[Finding] = []

    def add_item(self, item: ReportItem) -> None:
        """Adds a validation failure to the report.

        Args:
            item (ReportItem): The validation failure to be added.
        """
        self.report.append(Finding.from_report_item(item))
