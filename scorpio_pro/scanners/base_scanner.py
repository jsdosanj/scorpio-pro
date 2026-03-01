"""Abstract base class and Finding dataclass for all Scorpio Pro scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """Represents a single security finding produced by a scanner.

    Attributes:
        title: Short, descriptive title of the finding.
        severity: Risk level — Critical, High, Medium, Low, or Informational.
        description: Detailed explanation of what was found.
        evidence: Raw output or data that supports the finding.
        remediation: Recommended steps to address the finding.
        test_run: Name/identifier of the test that produced this finding.
        rationale: Why this test is important from a security perspective.
        methodology: How the test was conducted.
        status: Outcome of the test — ``pass``, ``fail``, or ``warning``.
        compliance_tags: Compliance control IDs this finding maps to.
        metadata: Arbitrary key-value pairs for scanner-specific data.
    """

    title: str
    severity: str  # Critical | High | Medium | Low | Informational
    description: str
    evidence: str
    remediation: str
    test_run: str
    rationale: str
    methodology: str
    status: str  # pass | fail | warning
    compliance_tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Severity ordering for sorting/scoring
    _SEVERITY_ORDER: dict[str, int] = field(
        default_factory=lambda: {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Informational": 1,
        },
        repr=False,
        compare=False,
    )

    def severity_score(self) -> int:
        """Return a numeric score for sorting by severity (higher = worse)."""
        return self._SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a plain dictionary."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "test_run": self.test_run,
            "rationale": self.rationale,
            "methodology": self.methodology,
            "status": self.status,
            "compliance_tags": self.compliance_tags,
            "metadata": self.metadata,
        }


class BaseScanner(ABC):
    """Abstract base class that all Scorpio Pro scanners must inherit from.

    Subclasses must implement :meth:`run` and :meth:`check_prerequisites`.
    """

    #: Human-readable name displayed in progress output.
    name: str = "BaseScanner"
    #: Short description shown in help text.
    description: str = ""

    def __init__(self, logger: Any = None) -> None:
        """Initialise the scanner with an optional logger.

        Args:
            logger: A :mod:`logging` logger instance.  If ``None``, a default
                module-level logger from :mod:`scorpio_pro.core.logger` is used.
        """
        if logger is None:
            from scorpio_pro.core.logger import get_logger
            self._log = get_logger(f"scorpio_pro.scanners.{self.__class__.__name__}")
        else:
            self._log = logger

    @abstractmethod
    def run(self, scope: Any) -> list[Finding]:
        """Execute the scanner against the provided scope.

        Args:
            scope: A :class:`~scorpio_pro.config.scope.ScopeConfig` instance
                describing what is authorised to be scanned.

        Returns:
            List of :class:`Finding` objects produced by the scan.
        """

    @abstractmethod
    def check_prerequisites(self) -> bool:
        """Verify that all required tools and libraries are available.

        Returns:
            ``True`` if all prerequisites are satisfied, ``False`` otherwise.
        """
