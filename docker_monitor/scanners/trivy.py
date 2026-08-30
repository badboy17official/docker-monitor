"""Trivy vulnerability scanner."""

from __future__ import annotations

import json
from typing import Dict

from docker_monitor.scanners.base import Scanner, ScanResult


class TrivyScanner(Scanner):
    name = "trivy"

    def available(self) -> bool:
        return self._tool_exists("trivy")

    def scan(self, image: str, timeout: int = 300) -> ScanResult:
        if not self.available():
            return ScanResult(
                scanner=self.name,
                findings={"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0},
            )

        result = self._run(["trivy", "image", "--format", "json", "--quiet", image], timeout=timeout)

        if result.returncode != 0 or not result.stdout.strip():
            return ScanResult(
                scanner=self.name,
                findings={"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1},
                raw_output=result.stdout + result.stderr,
                error=result.stderr,
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ScanResult(
                scanner=self.name,
                findings={"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1},
                raw_output=result.stdout,
                error="JSON parse error",
            )

        cves: Dict[str, set] = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
        for item in data.get("Results", []):
            for vuln in item.get("Vulnerabilities", []) or []:
                sev = (vuln.get("Severity") or "").upper()
                cve_id = vuln.get("VulnerabilityID")
                if sev in cves and cve_id:
                    cves[sev].add(cve_id)

        return ScanResult(
            scanner=self.name,
            findings={
                "critical": len(cves["CRITICAL"]),
                "high": len(cves["HIGH"]),
                "medium": len(cves["MEDIUM"]),
                "low": len(cves["LOW"]),
                "engine_enabled": 1,
            },
            cves_by_severity=cves,
            raw_output=result.stdout,
        )
