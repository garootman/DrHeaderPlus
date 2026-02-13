"""Base module for validators."""
from abc import ABC, abstractmethod
from typing import Any

from requests.structures import CaseInsensitiveDict

from drheader.report import ReportItem


class ValidatorBase(ABC):
    """Base class for validators."""

    @abstractmethod
    def exists(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header, directive or cookie exists in a set of headers.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def not_exists(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header, directive or cookie does not exist in a set of headers.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def value(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header or directive matches a single expected value.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def value_any_of(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header or directive matches one or more of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def value_one_of(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header or directive matches one of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def must_avoid(
        self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any,
    ) -> ReportItem | list[ReportItem] | None:
        """Validates that a header, directive or cookie does not contain any of a list of disallowed values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def must_contain(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header, directive or cookie contains all of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def must_contain_one(self, config: CaseInsensitiveDict[str, Any], header: str, **kwargs: Any) -> ReportItem | None:
        """Validates that a header, directive or cookie contains one or more of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """


class UnsupportedValidationError(Exception):
    """Exception to be raised when an unsupported validation is called.

    Attributes:
        message (string): A message describing the error.
    """

    def __init__(self, message: str) -> None:
        """Initialises an UnsupportedValidationError instance with a message."""
        self.message = message


def get_delimiter(config: CaseInsensitiveDict[str, Any], delimiter_type: str) -> str | None:
    if delimiters := config.get('delimiters'):
        return delimiters.get(delimiter_type)


def get_expected_values(config: CaseInsensitiveDict[str, Any], key: str, delimiter: str | None) -> list[str]:
    if isinstance(config[key], list):
        return [str(item).strip() for item in config[key]]
    else:
        return [item.strip() for item in str(config[key]).split(delimiter)]
