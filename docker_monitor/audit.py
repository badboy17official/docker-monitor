"""Multi-engine security audit orchestrator with parallel scanning."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel

from docker_monitor.config import Config
from docker_monitor.scanners.base import ScanResult
from docker_monitor.scanners.dockle import DockleScanner
from docker_monitor.scanners.grype import GrypeScanner
from docker_monitor.scanners.syft import SyftScanner
from docker_monitor.scanners.trivy import TrivyScanner
from docker_monitor.scoring.risk import RuleBasedRiskScorer

logger = logging.getLogger(__name__)
console = Console()


def _log_header(message: str):
    console.print(Panel(message, style="bold magenta"))
    logger.info(f"=== {message} ===")


def _run_command(command: List[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {command}")
        return subprocess.CompletedProcess(args=command, returncode=-1, stdout="", stderr="TimeoutExpired")


def _build_docker_image(dockerfile: str, image_name: str, context: str = ".") -> bool:
    logger.info(f"Building image: {image_name}")
    result = _run_command(["docker", "build", "-t", image_name, "-f", dockerfile, context], timeout=300)
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


def _run_scanners_parallel(image: str, output_file: str, config: Config) -> Dict[str, Any]:
    """Run all available scanners in parallel and aggregate results."""
    scan_cfg = config.scanning
    max_workers = scan_cfg.get("max_workers", 4)

    scanners = []
    if scan_cfg.get("trivy", {}).get("enabled", True):
        scanners.append(TrivyScanner())
    if scan_cfg.get("dockle", {}).get("enabled", True):
        scanners.append(DockleScanner())
    if scan_cfg.get("syft", {}).get("enabled", True):
        scanners.append(SyftScanner())
    if scan_cfg.get("grype", {}).get("enabled", True):
        scanners.append(GrypeScanner())

    results: Dict[str, ScanResult] = {}

    def run_scanner(scanner):
        timeout = scan_cfg.get(scanner.name, {}).get("timeout", 120)
        return scanner.name, scanner.scan(image, timeout=timeout)

    with ThreadPoolExecutor(max_workers=min(max_workers, len(scanners) or 1)) as executor:
        futures = {executor.submit(run_scanner, s): s for s in scanners}
        for future in as_completed(futures):
            try:
                name, result = future.result(timeout=300)
                results[name] = result
                if result.raw_output:
                    _append_report(output_file, f"{name.title()} - {image}", result.raw_output, result.error)
            except Exception as e:
                scanner = futures[future]
                logger.error(f"Scanner {scanner.name} failed: {e}")

    return _aggregate_results(results)


def _run_scanners_sequential(image: str, output_file: str, config: Config) -> Dict[str, Any]:
    """Run scanners sequentially (fallback)."""
    scan_cfg = config.scanning
    scanners = []
    if scan_cfg.get("trivy", {}).get("enabled", True):
        scanners.append(TrivyScanner())
    if scan_cfg.get("dockle", {}).get("enabled", True):
        scanners.append(DockleScanner())
    if scan_cfg.get("syft", {}).get("enabled", True):
        scanners.append(SyftScanner())
    if scan_cfg.get("grype", {}).get("enabled", True):
        scanners.append(GrypeScanner())

    results: Dict[str, ScanResult] = {}
    for scanner in scanners:
        timeout = scan_cfg.get(scanner.name, {}).get("timeout", 120)
        result = scanner.scan(image, timeout=timeout)
        results[scanner.name] = result
        if result.raw_output:
            _append_report(output_file, f"{scanner.name.title()} - {image}", result.raw_output, result.error)

    return _aggregate_results(results)


def _aggregate_results(results: Dict[str, ScanResult]) -> Dict[str, Any]:
    """Aggregate scan results with CVE deduplication across Trivy + Grype."""
    trivy = results.get("trivy")
    grype = results.get("grype")
    dockle = results.get("dockle")
    syft = results.get("syft")

    t_cves = trivy.cves_by_severity if trivy else {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    g_cves = grype.cves_by_severity if grype else {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}

    all_cves = set()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        all_cves.update(t_cves[sev])
        all_cves.update(g_cves[sev])

    engines_active = sum(1 for r in results.values() if r.findings.get("engine_enabled"))

    agg = {
        "critical": len(t_cves["CRITICAL"].union(g_cves["CRITICAL"])),
        "high": len(t_cves["HIGH"].union(g_cves["HIGH"])),
        "medium": len(t_cves["MEDIUM"].union(g_cves["MEDIUM"])),
        "low": len(t_cves["LOW"].union(g_cves["LOW"])),
        "fatal": dockle.findings.get("fatal", 0) if dockle else 0,
        "warn": dockle.findings.get("warn", 0) if dockle else 0,
        "packages": syft.findings.get("packages", 0) if syft else 0,
        "engines_active": engines_active,
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


def _enrich_cloud_cves(all_cve_ids: set, config: Config) -> Dict[str, str]:
    """Fetch CVE severity data from OSV.dev."""
    try:
        from docker_monitor.cve import CloudCVEFetcher

        fetcher = CloudCVEFetcher(config)
        return fetcher.fetch_severity(list(all_cve_ids))
    except Exception as e:
        logger.error(f"Cloud CVE sync failed: {e}")
        return {}


def _print_comparison(vulnerable: Dict[str, Any], hardened: Dict[str, Any]):
    _log_header("Multi-Engine Security Scan Comparison")
    logger.info(f"{'Metric':<28}{'Vulnerable':<16}{'Hardened':<16}{'Delta':<10}")
    logger.info("-" * 72)
    for key in ["critical", "high", "medium", "low", "fatal", "warn", "packages", "engines_active", "ai_risk_score"]:
        v = vulnerable.get(key, 0)
        h = hardened.get(key, 0)
        d = round(v - h, 2)
        logger.info(f"{key:<28}{str(v):<16}{str(h):<16}{str(d):<10}")


def run_audit(config: Config) -> Dict[str, Any]:
    """Run a full security audit on both vulnerable and hardened images."""
    _log_header("Container Security Audit Tool v2.8 - Multi Engine + AI")

    if not shutil.which("docker"):
        logger.error("Docker is not installed")
        sys.exit(1)

    images = config.images
    vuln_img = images.get("vulnerable", {})
    hard_img = images.get("hardened", {})

    vulnerable_image = vuln_img.get("name", "flask-app-vulnerable")
    hardened_image = hard_img.get("name", "flask-app-hardened")
    vuln_dockerfile = vuln_img.get("dockerfile", "Dockerfile.vuln")
    hard_dockerfile = hard_img.get("dockerfile", "Dockerfile.hardened")
    context = vuln_img.get("context", ".")

    if not _build_docker_image(vuln_dockerfile, vulnerable_image, context):
        sys.exit(1)
    if not _build_docker_image(hard_dockerfile, hardened_image, context):
        sys.exit(1)

    _log_header("Running Scanners")

    output_dir = Path(config.reporting.get("output_dir", "reports"))
    output_dir.mkdir(exist_ok=True)

    scan_fn = _run_scanners_parallel if config.scanning.get("parallel", True) else _run_scanners_sequential

    vulnerable_stats = scan_fn(vulnerable_image, str(output_dir / "scan_vulnerable.txt"), config)
    hardened_stats = scan_fn(hardened_image, str(output_dir / "scan_hardened.txt"), config)

    _print_comparison(vulnerable_stats, hardened_stats)

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
        from docker_monitor.alerts import AlertManager

        alert_mgr = AlertManager(config)
        if vulnerable_stats["ai_risk_score"] >= alert_mgr.threshold:
            alert_mgr.trigger_alert(
                vulnerable_stats["ai_risk_score"],
                "High audit risk score for vulnerable image",
                summary,
            )
    except Exception as e:
        logger.error(f"Alerting failed: {e}")

    summary_path = output_dir / "latest_multi_engine_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    try:
        from docker_monitor.reports import ReportGenerator

        reporter = ReportGenerator(str(output_dir))
        reporter.update_history(summary)
    except Exception as e:
        logger.error(f"Report generation failed: {e}")

    logger.info("Audit completed")
    logger.info(f"Saved: {summary_path}")

    return summary
