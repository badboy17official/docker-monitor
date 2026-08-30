"""Real-time Docker container threat monitoring engine."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from docker_monitor.alerts import AlertManager
from docker_monitor.config import Config
from docker_monitor.scoring.anomaly import EnsembleAnomalyDetector
from docker_monitor.scoring.ml import MLAnomalyDetector

logger = logging.getLogger(__name__)

try:
    import docker
except ImportError:
    docker = None


@dataclass
class ContainerSignal:
    container_id: str
    name: str
    image: str
    status: str
    cpu_percent: float
    memory_percent: float
    network_rx_mb: float
    network_tx_mb: float
    pids: int
    restart_count: int
    ai_anomaly_score: float
    score: int
    risk_level: str
    reasons: List[str]
    detectors_triggered: List[str]
    cve_critical: int
    cve_high: int
    top_cves: List[Dict[str, str]]
    recommended_fixes: List[str]
    timestamp: str


class VulnerabilityScanner:
    """Trivy-based vulnerability scanner with per-image caching."""

    def __init__(self, enabled: bool = True, cache_ttl_seconds: int = 900):
        self.enabled = enabled
        self.cache_ttl = cache_ttl_seconds
        self.cache: Dict[str, tuple] = {}

    @staticmethod
    def _tool_exists() -> bool:
        return shutil.which("trivy") is not None

    def _run_trivy(self, image: str) -> Dict[str, Any]:
        if not self.enabled or not self._tool_exists():
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "unavailable"}

        try:
            proc = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image],
                capture_output=True, text=True, check=False, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "timeout"}

        if proc.returncode != 0 or not proc.stdout.strip():
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "error"}

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "parse_error"}

        cves = []
        critical = high = 0
        fixes = set()

        for result in data.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                sev = (vuln.get("Severity") or "").upper()
                if sev == "CRITICAL":
                    critical += 1
                elif sev == "HIGH":
                    high += 1

                fixed = vuln.get("FixedVersion") or ""
                pkg = vuln.get("PkgName") or "unknown"
                installed = vuln.get("InstalledVersion") or "unknown"
                if fixed:
                    fixes.add(f"Update {pkg} from {installed} to {fixed}")

                cves.append({
                    "cve": vuln.get("VulnerabilityID", "N/A"),
                    "severity": sev or "UNKNOWN",
                    "package": pkg,
                    "installed_version": installed,
                    "fixed_version": fixed or "N/A",
                    "title": (vuln.get("Title") or "")[:120],
                })

        cves.sort(key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c["severity"], 9))
        return {
            "critical": critical,
            "high": high,
            "top_cves": cves[:8],
            "recommended_fixes": sorted(list(fixes))[:10],
            "scanner": "trivy",
        }

    def scan_image(self, image: str) -> Dict[str, Any]:
        now = time.time()
        cached = self.cache.get(image)
        if cached and (now - cached[0] < self.cache_ttl):
            return cached[1]
        result = self._run_trivy(image)
        self.cache[image] = (now, result)
        return result


class RuntimeThreatEngine:
    """Continuous runtime threat monitoring for Docker containers."""

    def __init__(self, config: Config):
        self.config = config
        rt = config.runtime

        self.interval_seconds = int(rt.get("poll_interval_seconds", 20))
        self.enabled = bool(rt.get("enabled", True))
        self.max_concurrent = int(rt.get("max_concurrent_scans", 3))

        vuln_cfg = config.vulnerability
        self.vuln_scanner = VulnerabilityScanner(
            enabled=bool(vuln_cfg.get("enabled", True)),
            cache_ttl_seconds=int(vuln_cfg.get("scan_cache_ttl_seconds", 900)),
        )

        window_size = int(rt.get("ai_window_size", 12))
        self.scorer = EnsembleAnomalyDetector(window_size=window_size)

        ml_cfg = config.ml
        self.ml_detector = MLAnomalyDetector(
            model_url=ml_cfg.get("model_url", ""),
            model_sha256=ml_cfg.get("model_sha256", ""),
        )

        self.alert_manager = AlertManager(config)

        if docker is None:
            raise RuntimeError("docker package not installed. Install with: pip install docker")

        self.hosts = rt.get("hosts", ["unix://var/run/docker.sock"])
        self.clients = []
        for host in self.hosts:
            try:
                if host in ("unix://var/run/docker.sock", "local"):
                    self.clients.append(docker.from_env())
                else:
                    self.clients.append(docker.DockerClient(base_url=host))
            except Exception as e:
                logger.error(f"Failed to connect to docker host {host}: {e}")

        self._output_dir = Path(config.reporting.get("output_dir", "reports")).parent / "runtime"
        self._output_file = self._output_dir / "runtime_threats_latest.json"

    @staticmethod
    def _safe_num(value: Any) -> float:
        try:
            return max(float(value), 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _calc_cpu_percent(stats: Dict[str, Any]) -> float:
        cpu_stats = stats.get("cpu_stats", {})
        precpu = stats.get("precpu_stats", {})
        cpu_delta = (
            cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            - precpu.get("cpu_usage", {}).get("total_usage", 0)
        )
        sys_delta = cpu_stats.get("system_cpu_usage", 0) - precpu.get("system_cpu_usage", 0)
        cpus = cpu_stats.get("online_cpus") or len(
            cpu_stats.get("cpu_usage", {}).get("percpu_usage", []) or [1]
        )
        if sys_delta > 0 and cpu_delta > 0:
            return (cpu_delta / sys_delta) * cpus * 100.0
        return 0.0

    @staticmethod
    def _calc_memory_percent(stats: Dict[str, Any]) -> float:
        mem = stats.get("memory_stats", {})
        usage = float(mem.get("usage", 0))
        limit = float(mem.get("limit", 0))
        return (usage / limit) * 100.0 if limit > 0 else 0.0

    @staticmethod
    def _calc_network_mb(stats: Dict[str, Any]) -> Dict[str, float]:
        networks = stats.get("networks", {}) or {}
        rx = sum(v.get("rx_bytes", 0) for v in networks.values()) / (1024 * 1024)
        tx = sum(v.get("tx_bytes", 0) for v in networks.values()) / (1024 * 1024)
        return {"rx": rx, "tx": tx}

    def collect_signals(self) -> List[ContainerSignal]:
        findings: List[ContainerSignal] = []
        containers = []
        for client in self.clients:
            try:
                containers.extend(client.containers.list())
            except Exception as e:
                logger.error(f"Failed to list containers: {e}")

        from docker_monitor import db

        def process_container(container) -> ContainerSignal:
            stats = container.stats(stream=False)
            net = self._calc_network_mb(stats)
            image_ref = container.image.tags[0] if container.image.tags else container.image.short_id
            vuln = self.vuln_scanner.scan_image(image_ref)

            cpu = self._safe_num(self._calc_cpu_percent(stats))
            mem = self._safe_num(self._calc_memory_percent(stats))
            net_rx = self._safe_num(net["rx"])
            net_tx = self._safe_num(net["tx"])
            pids = int((stats.get("pids_stats") or {}).get("current", 0))
            restart_count = int((container.attrs or {}).get("RestartCount", 0))
            container_id = container.id[:12]

            is_protected = db.is_container_protected(container_id)

            ml_score = self.ml_detector.score({
                "cpu": cpu, "memory": mem, "network_total": net_rx + net_tx,
                "pids": pids, "restart_count": restart_count,
                "cpu_z": 0, "memory_z": 0, "network_z": 0, "pid_z": 0,
            })

            scored = self.scorer.score(
                container_id=container_id,
                cpu=cpu, mem=mem, net=net_rx + net_tx, pids=pids,
                restart_count=restart_count,
                cve_critical=vuln.get("critical", 0),
                cve_high=vuln.get("high", 0),
                ml_score=ml_score,
            )

            threshold = self.alert_manager.threshold - 20 if is_protected else self.alert_manager.threshold
            self.alert_manager.trigger_alert(
                scored["score"],
                f"{'[PROTECTED] ' if is_protected else ''}High threat score for {container.name} (image: {image_ref})",
                scored,
                threshold_override=threshold,
            )

            return ContainerSignal(
                container_id=container_id,
                name=container.name,
                image=image_ref,
                status=container.status,
                cpu_percent=cpu,
                memory_percent=mem,
                network_rx_mb=net_rx,
                network_tx_mb=net_tx,
                pids=pids,
                restart_count=restart_count,
                ai_anomaly_score=scored["ai_anomaly_score"],
                score=scored["score"],
                risk_level=scored["risk_level"],
                reasons=scored["reasons"],
                detectors_triggered=scored["detectors_triggered"],
                cve_critical=int(vuln.get("critical", 0)),
                cve_high=int(vuln.get("high", 0)),
                top_cves=vuln.get("top_cves", []),
                recommended_fixes=vuln.get("recommended_fixes", []),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        max_w = min(self.max_concurrent, len(containers) or 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as executor:
            future_to_c = {executor.submit(process_container, c): c for c in containers}
            for future in concurrent.futures.as_completed(future_to_c):
                c = future_to_c[future]
                try:
                    findings.append(future.result(timeout=15.0))
                except concurrent.futures.TimeoutError:
                    logger.error(f"Timeout analyzing container {c.name}")
                except Exception:
                    logger.exception(f"Failed analyzing container {c.name}")

        return findings

    def _build_alerts(self, signals: List[ContainerSignal]) -> List[Dict[str, Any]]:
        alerts = []
        for s in signals:
            if s.risk_level in ("critical", "high") or s.cve_critical > 0:
                alerts.append({
                    "container": s.name,
                    "risk_level": s.risk_level,
                    "runtime_score": s.score,
                    "ai_anomaly_score": s.ai_anomaly_score,
                    "cve_critical": s.cve_critical,
                    "cve_high": s.cve_high,
                    "top_cve": s.top_cves[0] if s.top_cves else None,
                    "recommended_fix": s.recommended_fixes[0] if s.recommended_fixes else None,
                    "timestamp": s.timestamp,
                })
        return alerts

    def export_local(self, signals: List[ContainerSignal]) -> Dict[str, Any]:
        self._output_dir.mkdir(parents=True, exist_ok=True)

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_critical = total_high = 0
        for s in signals:
            risk[s.risk_level] += 1
            total_critical += s.cve_critical
            total_high += s.cve_high

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "containers_monitored": len(signals),
                "critical_alerts": risk["critical"],
                "high_alerts": risk["high"],
                "medium_alerts": risk["medium"],
                "low_alerts": risk["low"],
                "mean_ai_anomaly_score": (
                    round(sum(s.ai_anomaly_score for s in signals) / len(signals), 2)
                    if signals else 0
                ),
                "total_cve_critical": total_critical,
                "total_cve_high": total_high,
                "containers_with_vulns": sum(1 for s in signals if s.cve_critical > 0 or s.cve_high > 0),
            },
            "alerts": self._build_alerts(signals),
            "findings": [asdict(s) for s in signals],
        }

        with open(self._output_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        try:
            from docker_monitor import db

            for alert in payload.get("alerts", []):
                db.save_runtime_event(alert)
        except Exception as e:
            logger.error(f"Failed to save runtime events to DB: {e}")

        return payload

    def generate_report(self, payload: Dict[str, Any], fmt: str = "json") -> Path:
        reports_dir = Path(self.config.reporting.get("output_dir", "reports"))
        reports_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "txt":
            out = reports_dir / f"runtime_security_report_{ts}.txt"
            s = payload.get("summary", {})
            lines = [
                "Runtime Security Report",
                "=" * 72,
                f"Generated: {payload.get('generated_at')}",
                f"Containers monitored: {s.get('containers_monitored', 0)}",
                f"Runtime alerts (critical/high): {s.get('critical_alerts', 0)}/{s.get('high_alerts', 0)}",
                f"CVEs critical/high: {s.get('total_cve_critical', 0)}/{s.get('total_cve_high', 0)}",
                "",
                "Alerts:",
            ]
            for a in payload.get("alerts", []):
                line = (
                    f"- {a['container']} | risk={a['risk_level']} "
                    f"score={a['runtime_score']} ai={a['ai_anomaly_score']} "
                    f"CVE(C/H)={a['cve_critical']}/{a['cve_high']} "
                    f"fix={a.get('recommended_fix') or 'n/a'}"
                )
                lines.append(line)
            out.write_text("\n".join(lines), encoding="utf-8")
            return out

        out = reports_dir / f"runtime_security_report_{ts}.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out

    def run_once(self) -> Dict[str, Any]:
        return self.export_local(self.collect_signals())

    def run_forever(self):
        if not self.enabled:
            logger.info("Runtime monitoring disabled")
            return
        logger.info(f"Runtime Threat Engine running every {self.interval_seconds}s")
        while True:
            try:
                payload = self.run_once()
                s = payload["summary"]
                logger.info(
                    f"monitored={s['containers_monitored']} "
                    f"critical={s['critical_alerts']} "
                    f"high={s['high_alerts']} "
                    f"cveCritical={s['total_cve_critical']} "
                    f"ai_mean={s['mean_ai_anomaly_score']}"
                )
            except KeyboardInterrupt:
                logger.info("Stopped")
                break
            except Exception as exc:
                logger.exception(f"Cycle failed: {exc}")
            time.sleep(self.interval_seconds)
