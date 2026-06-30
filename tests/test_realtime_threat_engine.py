import pytest
from unittest.mock import MagicMock, patch
from realtime_threat_engine import ThreatScorer, RuntimeThreatEngine, VulnerabilityScanner

def test_threat_scorer():
    scorer = ThreatScorer()
    metrics = {
        "container_id": "test1234",
        "cpu_percent": 95.0, # high CPU
        "memory_percent": 90.0, # high Memory
        "network_rx_mb": 500.0,
        "network_tx_mb": 100.0,
        "pids": 300,
        "restart_count": 5
    }
    # First score, ewma won't trigger spike yet, but rules will
    result = scorer.score(metrics, cve_critical=2, cve_high=1)
    
    assert "score" in result
    assert result["score"] > 50
    assert "risk_level" in result
    assert "critical" in result["risk_level"] or "high" in result["risk_level"]
    assert any("CPU" in reason for reason in result["reasons"])
    assert "rule" in result["detectors_triggered"]
    assert "vuln_cve" in result["detectors_triggered"]

@patch('subprocess.run')
def test_vulnerability_scanner(mock_run):
    import json
    mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps({
        "Results": [{"Vulnerabilities": [{"Severity": "CRITICAL", "VulnerabilityID": "CVE-123"}]}]
    }))
    
    scanner = VulnerabilityScanner(enabled=True)
    with patch('shutil.which', return_value="/usr/bin/trivy"):
        result = scanner.scan_image("test-image")
        assert result["critical"] == 1
        assert result["high"] == 0
        assert result["top_cves"][0]["cve"] == "CVE-123"

@patch('docker.from_env')
def test_runtime_threat_engine_collect(mock_docker_env):
    mock_client = MagicMock()
    mock_docker_env.return_value = mock_client
    
    mock_container = MagicMock()
    mock_container.id = "abcdef123456"
    mock_container.name = "test-container"
    mock_container.image.tags = ["test-image:latest"]
    mock_container.status = "running"
    mock_container.stats.return_value = {
        "cpu_stats": {"cpu_usage": {"total_usage": 1000}, "system_cpu_usage": 2000, "online_cpus": 1},
        "precpu_stats": {"cpu_usage": {"total_usage": 500}, "system_cpu_usage": 1000},
        "memory_stats": {"usage": 500000, "limit": 1000000},
        "networks": {"eth0": {"rx_bytes": 1048576, "tx_bytes": 1048576}},
        "pids_stats": {"current": 10}
    }
    mock_container.attrs = {"RestartCount": 0}
    
    mock_client.containers.list.return_value = [mock_container]
    
    engine = RuntimeThreatEngine()
    engine.vuln_scanner = MagicMock()
    engine.vuln_scanner.scan_image.return_value = {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": []}
    
    signals = engine.collect_signals()
    assert len(signals) == 1
    assert signals[0].name == "test-container"
    assert signals[0].cpu_percent > 0
    assert signals[0].memory_percent == 50.0
