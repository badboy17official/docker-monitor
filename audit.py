#!/usr/bin/env python3
"""Container Security Audit with Multi-Engine Scanning + AI Risk Scoring."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ai_security_model import PretrainedRiskModel


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(message: str):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*78}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{message.center(78)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*78}{Colors.ENDC}\n")


def print_info(message: str):
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} {message}")


def print_success(message: str):
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} {message}")


def print_warning(message: str):
    print(f"{Colors.WARNING}[!]{Colors.ENDC} {message}")


def print_error(message: str):
    print(f"{Colors.FAIL}[✗]{Colors.ENDC} {message}")


def run_command(command: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def check_tool_installed(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def build_docker_image(dockerfile_path: str, image_name: str) -> bool:
    print_info(f"Building image: {image_name}")
    result = run_command(["docker", "build", "-t", image_name, "-f", dockerfile_path, "."])
    if result.returncode == 0:
        print_success(f"Successfully built: {image_name}")
        return True
    print_error(f"Failed to build: {image_name}\n{result.stderr}")
    return False


def _append_report(output_file: str, section: str, stdout: str, stderr: str):
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"\n\n{'='*78}\n{section}\nGenerated: {datetime.now().isoformat()}\n{'='*78}\n")
        if stdout:
            f.write(stdout)
        if stderr:
            f.write("\n\n[stderr]\n")
            f.write(stderr)


def scan_trivy(image_name: str, output_file: str) -> Dict[str, int]:
    if not check_tool_installed("trivy"):
        print_warning("Trivy not found")
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0}

    result = run_command(["trivy", "image", "--format", "json", image_name])
    _append_report(output_file, f"Trivy - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0 or not result.stdout.strip():
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1}

    data = json.loads(result.stdout)
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in data.get("Results", []):
        for vuln in item.get("Vulnerabilities", []) or []:
            s = vuln.get("Severity", "")
            if s in sev:
                sev[s] += 1
    return {
        "critical": sev["CRITICAL"],
        "high": sev["HIGH"],
        "medium": sev["MEDIUM"],
        "low": sev["LOW"],
        "engine_enabled": 1,
    }


def scan_dockle(image_name: str, output_file: str) -> Dict[str, int]:
    if not check_tool_installed("dockle"):
        print_warning("Dockle not found")
        return {"fatal": 0, "warn": 0, "engine_enabled": 0}

    result = run_command(["dockle", "-f", "json", image_name])
    _append_report(output_file, f"Dockle - {image_name}", result.stdout, result.stderr)

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
    return {"fatal": fatal, "warn": warn, "engine_enabled": 1}


def scan_syft(image_name: str, output_file: str) -> Dict[str, int]:
    if not check_tool_installed("syft"):
        print_warning("Syft not found")
        return {"packages": 0, "engine_enabled": 0}
    result = run_command(["syft", image_name, "-o", "json"])
    _append_report(output_file, f"Syft SBOM - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0:
        return {"packages": 0, "engine_enabled": 1}
    try:
        data = json.loads(result.stdout)
        return {"packages": len(data.get("artifacts", [])), "engine_enabled": 1}
    except json.JSONDecodeError:
        return {"packages": 0, "engine_enabled": 1}


def scan_grype(image_name: str, output_file: str) -> Dict[str, int]:
    if not check_tool_installed("grype"):
        print_warning("Grype not found")
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0}

    result = run_command(["grype", image_name, "-o", "json"])
    _append_report(output_file, f"Grype - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0 or not result.stdout.strip():
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1}

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        data = json.loads(result.stdout)
        for m in data.get("matches", []):
            s = (m.get("vulnerability") or {}).get("severity", "")
            if s in sev:
                sev[s] += 1
    except json.JSONDecodeError:
        pass
    return {
        "critical": sev["Critical"],
        "high": sev["High"],
        "medium": sev["Medium"],
        "low": sev["Low"],
        "engine_enabled": 1,
    }


def aggregate_scan(image_name: str, output_file: str) -> Dict[str, Any]:
    if Path(output_file).exists():
        Path(output_file).unlink()

    trivy = scan_trivy(image_name, output_file)
    dockle = scan_dockle(image_name, output_file)
    syft = scan_syft(image_name, output_file)
    grype = scan_grype(image_name, output_file)

    # aggregate vulnerabilities by taking max across CVE engines (trivy/grype)
    agg = {
        "critical": max(trivy["critical"], grype["critical"]),
        "high": max(trivy["high"], grype["high"]),
        "medium": max(trivy["medium"], grype["medium"]),
        "low": max(trivy["low"], grype["low"]),
        "fatal": dockle["fatal"],
        "warn": dockle["warn"],
        "packages": syft["packages"],
        "engines_active": trivy["engine_enabled"] + dockle["engine_enabled"] + syft["engine_enabled"] + grype["engine_enabled"],
    }

    model = PretrainedRiskModel()
    agg["ai_risk_score"] = model.score({
        "critical": agg["critical"],
        "high": agg["high"],
        "medium": agg["medium"],
        "low": agg["low"],
        "fatal": agg["fatal"],
        "warn": agg["warn"],
        "engine_coverage": agg["engines_active"],
    })
    return agg


def print_comparison(vulnerable: Dict[str, Any], hardened: Dict[str, Any]):
    print_header("Multi-Engine Security Scan Comparison")
    print(f"{'Metric':<28}{'Vulnerable':<16}{'Hardened':<16}{'Delta':<10}")
    print("-" * 72)
    for key in ["critical", "high", "medium", "low", "fatal", "warn", "packages", "engines_active", "ai_risk_score"]:
        v = vulnerable.get(key, 0)
        h = hardened.get(key, 0)
        d = round(v - h, 2)
        print(f"{key:<28}{str(v):<16}{str(h):<16}{str(d):<10}")


def main():
    print_header("Container Security Audit Tool - Multi Engine + AI")
    if not check_tool_installed("docker"):
        print_error("Docker is not installed")
        sys.exit(1)

    vulnerable_image = "flask-app-vulnerable"
    hardened_image = "flask-app-hardened"

    if not build_docker_image("Dockerfile.vuln", vulnerable_image):
        sys.exit(1)
    if not build_docker_image("Dockerfile.hardened", hardened_image):
        sys.exit(1)

    print_header("Running Scanners")
    vulnerable_stats = aggregate_scan(vulnerable_image, "scan_vulnerable.txt")
    hardened_stats = aggregate_scan(hardened_image, "scan_hardened.txt")

    print_comparison(vulnerable_stats, hardened_stats)

    summary = {
        "timestamp": datetime.now().isoformat(),
        "vulnerable": vulnerable_stats,
        "hardened": hardened_stats,
        "comparison": {
            "ai_risk_drop": round(vulnerable_stats["ai_risk_score"] - hardened_stats["ai_risk_score"], 2),
            "critical_drop": vulnerable_stats["critical"] - hardened_stats["critical"],
            "high_drop": vulnerable_stats["high"] - hardened_stats["high"],
            "engines_active": {
                "vulnerable": vulnerable_stats["engines_active"],
                "hardened": hardened_stats["engines_active"],
            },
        },
    }

    Path("reports").mkdir(exist_ok=True)
    with open("reports/latest_multi_engine_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print_success("Audit completed")
    print_info("Saved: scan_vulnerable.txt, scan_hardened.txt, reports/latest_multi_engine_summary.json")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("Interrupted by user")
        sys.exit(1)
