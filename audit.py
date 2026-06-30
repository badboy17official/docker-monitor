#!/usr/bin/env python3
"""Container Security Audit with Multi-Engine Scanning + AI Risk Scoring."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

from ai_security_model import RuleBasedRiskScorer

# Setup logging
os.makedirs("logs", exist_ok=True)
logger = logging.getLogger("audit")
logger.setLevel(logging.INFO)

fh = logging.FileHandler("logs/audit.log")
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(ch)

console = Console()

def log_header(message: str):
    console.print(Panel(message, style="bold magenta"))
    logger.info(f"=== {message} ===")

def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after 120s: {command}")
        return subprocess.CompletedProcess(args=command, returncode=-1, stdout="", stderr="TimeoutExpired")

def check_tool_installed(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None

def build_docker_image(dockerfile_path: str, image_name: str) -> bool:
    logger.info(f"Building image: {image_name}")
    result = run_command(["docker", "build", "-t", image_name, "-f", dockerfile_path, "."])
    if result.returncode == 0:
        logger.info(f"Successfully built: {image_name}")
        return True
    logger.error(f"Failed to build: {image_name}\n{result.stderr}")
    return False

def _append_report(output_file: str, section: str, stdout: str, stderr: str):
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"\n\n{'='*78}\n{section}\nGenerated: {datetime.now().isoformat()}\n{'='*78}\n")
        if stdout:
            f.write(stdout)
        if stderr:
            f.write("\n\n[stderr]\n")
            f.write(stderr)

def scan_trivy(image_name: str, output_file: str) -> dict[str, Any]:
    empty_cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    if not check_tool_installed("trivy"):
        logger.warning("Trivy not found")
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0, "cves_by_severity": empty_cves}

    result = run_command(["trivy", "image", "--format", "json", image_name])
    _append_report(output_file, f"Trivy - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0 or not result.stdout.strip():
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1, "cves_by_severity": empty_cves}

    data = json.loads(result.stdout)
    cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    for item in data.get("Results", []):
        for vuln in item.get("Vulnerabilities", []) or []:
            s = vuln.get("Severity", "").upper()
            cve_id = vuln.get("VulnerabilityID")
            if s in cves and cve_id:
                cves[s].add(cve_id)
    return {
        "critical": len(cves["CRITICAL"]),
        "high": len(cves["HIGH"]),
        "medium": len(cves["MEDIUM"]),
        "low": len(cves["LOW"]),
        "cves_by_severity": cves,
        "engine_enabled": 1,
    }

def scan_dockle(image_name: str, output_file: str) -> dict[str, Any]:
    if not check_tool_installed("dockle"):
        logger.warning("Dockle not found")
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

def scan_syft(image_name: str, output_file: str) -> dict[str, Any]:
    if not check_tool_installed("syft"):
        logger.warning("Syft not found")
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

def scan_grype(image_name: str, output_file: str) -> dict[str, Any]:
    empty_cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    if not check_tool_installed("grype"):
        logger.warning("Grype not found")
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0, "cves_by_severity": empty_cves}

    result = run_command(["grype", image_name, "-o", "json"])
    _append_report(output_file, f"Grype - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0 or not result.stdout.strip():
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1, "cves_by_severity": empty_cves}

    cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    try:
        data = json.loads(result.stdout)
        for m in data.get("matches", []):
            s = (m.get("vulnerability", {}).get("severity", "")).upper()
            cve_id = m.get("vulnerability", {}).get("id")
            if s in cves and cve_id:
                cves[s].add(cve_id)
    except json.JSONDecodeError:
        pass
    return {
        "critical": len(cves["CRITICAL"]),
        "high": len(cves["HIGH"]),
        "medium": len(cves["MEDIUM"]),
        "low": len(cves["LOW"]),
        "cves_by_severity": cves,
        "engine_enabled": 1,
    }

def aggregate_scan(image_name: str, output_file: str) -> dict[str, Any]:
    if Path(output_file).exists():
        Path(output_file).unlink()

    trivy = scan_trivy(image_name, output_file)
    dockle = scan_dockle(image_name, output_file)
    syft = scan_syft(image_name, output_file)
    grype = scan_grype(image_name, output_file)

    t_cves = trivy.get("cves_by_severity", {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()})
    g_cves = grype.get("cves_by_severity", {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()})

    agg = {
        "critical": len(t_cves["CRITICAL"].union(g_cves["CRITICAL"])),
        "high": len(t_cves["HIGH"].union(g_cves["HIGH"])),
        "medium": len(t_cves["MEDIUM"].union(g_cves["MEDIUM"])),
        "low": len(t_cves["LOW"].union(g_cves["LOW"])),
        "fatal": dockle["fatal"],
        "warn": dockle["warn"],
        "packages": syft["packages"],
        "engines_active": trivy["engine_enabled"] + dockle["engine_enabled"] + syft["engine_enabled"] + grype["engine_enabled"],
    }

    model = RuleBasedRiskScorer()
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

def print_comparison(vulnerable: dict[str, Any], hardened: dict[str, Any]):
    log_header("Multi-Engine Security Scan Comparison")
    logger.info(f"{'Metric':<28}{'Vulnerable':<16}{'Hardened':<16}{'Delta':<10}")
    logger.info("-" * 72)
    for key in ["critical", "high", "medium", "low", "fatal", "warn", "packages", "engines_active", "ai_risk_score"]:
        v = vulnerable.get(key, 0)
        h = hardened.get(key, 0)
        d = round(v - h, 2)
        logger.info(f"{key:<28}{str(v):<16}{str(h):<16}{str(d):<10}")

def main():
    log_header("Container Security Audit Tool - Multi Engine + AI")
    if not check_tool_installed("docker"):
        logger.error("Docker is not installed")
        sys.exit(1)

    vulnerable_image = "flask-app-vulnerable"
    hardened_image = "flask-app-hardened"

    if not build_docker_image("Dockerfile.vuln", vulnerable_image):
        sys.exit(1)
    if not build_docker_image("Dockerfile.hardened", hardened_image):
        sys.exit(1)

    log_header("Running Scanners")
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

    try:
        import yaml
        from alerting import AlertManager
        with open("config.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        alert_manager = AlertManager(config)
        if hardened_stats["ai_risk_score"] >= alert_manager.threshold:
            alert_manager.trigger_alert(
                hardened_stats["ai_risk_score"],
                "High audit risk score for hardened image",
                summary
            )
    except Exception as e:
        logger.error(f"Alerting failed: {e}")

    Path("reports").mkdir(exist_ok=True)
    with open("reports/latest_multi_engine_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Audit completed")
    logger.info("Saved: scan_vulnerable.txt, scan_hardened.txt, reports/latest_multi_engine_summary.json")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(1)
