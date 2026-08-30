"""Grype vulnerability scanner."""

from __future__ import annotations

import json
from typing import Dict

from docker_monitor.scanners.base import Scanner, ScanResult


class GrypeScanner(Scanner):
    name = "grype"

    def available(self) -> bool:
        return self._tool_exists("grype")

    def scan(self, image: str, timeout: int = 120) -> ScanResult:
        if not self.available():
            return ScanResult(
                scanner=self.name,
                findings={"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0},
            )

        result = self._run(["grype", image, "-o", "json"], timeout=timeout)

        if result.returncode != 0 or not result.stdout.strip():
            return ScanResult(
                scanner=self.name,
                findings={"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1},
                raw_output=result.stdout + result.stderr,
                error=result.stderr,
            )

        cves: Dict[str, set] = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
        try:
            data = json.loads(result.stdout)
            for m in data.get("matches", []):
                sev = (m.get("vulnerability", {}).get("severity", "")).upper()
                cve_id = m.get("vulnerability", {}).get("id")
                if sev in cves and cve_id:
                    cves[sev].add(cve_id)
        except json.JSONDecodeError:
            pass

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
