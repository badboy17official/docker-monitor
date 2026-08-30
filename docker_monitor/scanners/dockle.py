"""Dockle container image linter."""

from __future__ import annotations

import json

from docker_monitor.scanners.base import Scanner, ScanResult


class DockleScanner(Scanner):
    name = "dockle"

    def available(self) -> bool:
        return self._tool_exists("dockle")

    def scan(self, image: str, timeout: int = 120) -> ScanResult:
        if not self.available():
            return ScanResult(scanner=self.name, findings={"fatal": 0, "warn": 0, "engine_enabled": 0})

        result = self._run(["dockle", "-f", "json", image], timeout=timeout)

        fatal = warn = 0
        try:
            data = json.loads(result.stdout) if result.stdout else {}
            details = data.get("details", []) if isinstance(data, dict) else []
            for d in details:
                level = (d.get("level") or "").upper()
                if level == "FATAL":
                    fatal += 1
                elif level == "WARN":
                    warn += 1
        except json.JSONDecodeError:
            pass

        return ScanResult(
            scanner=self.name,
            findings={"fatal": fatal, "warn": warn, "engine_enabled": 1},
            raw_output=result.stdout + result.stderr,
        )
