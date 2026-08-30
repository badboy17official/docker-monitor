"""Abstract base scanner interface."""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ScanResult:
    """Result from a single scanner run."""
    scanner: str
    findings: Dict[str, Any]
    raw_output: str = ""
    duration: float = 0.0
    error: str = ""
    cves_by_severity: Dict[str, set] = field(default_factory=lambda: {
        "CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()
    })


class Scanner(ABC):
    """Abstract base class for security scanners."""

    name: str = "base"

    @abstractmethod
    def available(self) -> bool:
        """Check if the scanner tool is installed."""
        ...

    @abstractmethod
    def scan(self, image: str, timeout: int = 120) -> ScanResult:
        """Run the scanner against a Docker image."""
        ...

    @staticmethod
    def _run(cmd: List[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        )

    @staticmethod
    def _tool_exists(name: str) -> bool:
        return shutil.which(name) is not None
