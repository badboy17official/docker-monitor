"""Syft SBOM generator."""

from __future__ import annotations

import json

from docker_monitor.scanners.base import Scanner, ScanResult


class SyftScanner(Scanner):
    name = "syft"

    def available(self) -> bool:
        return self._tool_exists("syft")

    def scan(self, image: str, timeout: int = 120) -> ScanResult:
        if not self.available():
            return ScanResult(scanner=self.name, findings={"packages": 0, "engine_enabled": 0})

        result = self._run(["syft", image, "-o", "json"], timeout=timeout)

        if result.returncode != 0:
            return ScanResult(
                scanner=self.name,
                findings={"packages": 0, "engine_enabled": 1},
                raw_output=result.stdout + result.stderr,
                error=result.stderr,
            )

        try:
            data = json.loads(result.stdout)
            return ScanResult(
                scanner=self.name,
                findings={"packages": len(data.get("artifacts", [])), "engine_enabled": 1},
                raw_output=result.stdout,
            )
        except json.JSONDecodeError:
            return ScanResult(
                scanner=self.name,
                findings={"packages": 0, "engine_enabled": 1},
                raw_output=result.stdout,
                error="JSON parse error",
            )
