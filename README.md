# 🐳 docker-monitor

> Multi-engine Docker container security audit platform with real-time runtime threat monitoring, web dashboard, and CI/CD integration.

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Trivy](https://img.shields.io/badge/Trivy-Scanner-blue?style=for-the-badge)](https://github.com/aquasecurity/trivy)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://github.com/noble6/docker-monitor/blob/main/LICENSE)
[![Security Audit](https://img.shields.io/badge/Security-Audit-red?style=for-the-badge)](https://github.com/noble6/docker-monitor)

---

## What is this?

**docker-monitor** is an automated container security audit platform that builds, scans, and compares a vulnerable Flask image against a hardened one — using four scanning engines simultaneously. It also runs a continuous runtime threat engine that monitors live containers for anomalous behavior.

Built as a DevSecOps learning platform and portfolio project by a Cybersecurity engineering student.

---

## Features

- **Multi-engine scanning** — Trivy, Dockle, Syft, Grype running in parallel
- **CVE deduplication** — results unified by CVE ID across engines, not just max counts
- **Real-time runtime monitoring** — z-score, EWMA, and rule-based anomaly detection on live containers
- **Web dashboard** — Flask + Chart.js UI with live metrics, container controls, and audit triggers
- **CI/CD integration** — GitHub Actions and GitLab CI pipelines with threshold enforcement
- **Kubernetes manifests** — hardened and vulnerable K8s configs for comparison
- **Multi-format reports** — JSON, HTML, and plaintext output
- **Rule-based risk scoring** — transparent weighted heuristic scorer (no fake AI claims)

---

## Architecture
audit.py ──► [Trivy / Dockle / Syft / Grype] ──► reports/
│
└──► ai_security_model.py (RuleBasedRiskScorer)
realtime_threat_engine.py ──► Docker API ──► ThreatScorer ──► runtime/
│
└──► VulnerabilityScanner (Trivy, cached per image)
dashboard/app.py ──► Flask ──► http://localhost:8080

---

## Directory Structure
docker-monitor/
├── audit.py                    # Main multi-engine audit script
├── realtime_threat_engine.py   # Runtime container threat monitor
├── ai_security_model.py        # Rule-based risk and anomaly scorers
├── report_generator.py         # Multi-format report generator
├── config.yaml                 # All runtime and scan configuration
├── docker-compose.yml          # Full stack orchestration
├── Dockerfile.vuln             # Intentionally insecure image (demo)
├── Dockerfile.hardened         # Production-hardened image
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Project metadata and dev dependencies
├── app/                        # Flask demo application
├── dashboard/                  # Web dashboard server + templates
├── k8s/                        # Kubernetes manifests
│   ├── deployment-vulnerable.yaml
│   └── deployment-hardened.yaml
├── tests/                      # pytest unit tests
│   └── test_audit.py
├── .github/workflows/          # GitHub Actions CI pipeline
├── .gitlab-ci.yml              # GitLab CI pipeline
├── ARCHITECTURE.md             # Detailed architecture docs
├── CONTRIBUTING.md             # Contribution guide
├── CHANGELOG.md                # Version history
└── LICENSE                     # MIT License

---

## Prerequisites

**Required:**
- Docker
- Python 3.10+

**Optional (enables full scanning):**
- [Trivy](https://github.com/aquasecurity/trivy)
- [Dockle](https://github.com/goodwithtech/dockle)
- [Syft](https://github.com/anchore/syft)
- [Grype](https://github.com/anchore/grype)

The tool gracefully skips any scanner that isn't installed.

### Required Tools Installation (Linux)

To ensure the security scan uses all 4 available engines, install the required binaries on your host machine:

**Debian/Ubuntu:**
```bash
# Trivy
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Dockle
VERSION=$(curl --silent "https://api.github.com/repos/goodwithtech/dockle/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
wget https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.deb
sudo dpkg -i dockle_${VERSION}_Linux-64bit.deb

# Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

**Arch Linux:**
```bash
sudo pacman -S trivy syft grype
# Dockle is available in the AUR
yay -S dockle-bin
```

---

## Quick Start

**1. Clone and install:**
```bash
git clone https://github.com/noble6/docker-monitor.git
cd docker-monitor
pip install -r requirements.txt
```

**2. Run the audit:**
```bash
python audit.py
```
Outputs: `scan_vulnerable.txt`, `scan_hardened.txt`, `reports/latest_multi_engine_summary.json`

**3. Launch the dashboard:**
```bash
python dashboard/app.py
# Open: http://localhost:8080
```

**4. Docker Compose (full stack):**
```bash
export DASHBOARD_AUTH_USER=admin
export DASHBOARD_AUTH_PASSWORD=changeme

docker-compose up -d
# Vulnerable app:  http://localhost:5001
# Hardened app:    http://localhost:5002
# Dashboard:       http://localhost:8080

docker-compose down
```

**5. Kubernetes:**
```bash
kubectl apply -f k8s/deployment-hardened.yaml
kubectl get all -n flask-hardened
```

---

## Runtime Threat Engine

Monitors all running Docker containers continuously and scores anomalous behavior.

```bash
# Continuous mode (default)
python realtime_threat_engine.py

# Single snapshot
RUNTIME_MONITOR_MODE=once python realtime_threat_engine.py

# Generate report after snapshot
RUNTIME_MONITOR_MODE=once RUNTIME_REPORT_FORMAT=json python realtime_threat_engine.py
```

**What it detects:**
- CPU / memory spikes (rule + z-score + EWMA)
- PID count anomalies (possible fork bombs / spawn bursts)
- Network throughput spikes (possible data exfiltration)
- Restart churn
- CVEs present on running image (Trivy, cached 15 min)

**Output:** `runtime/runtime_threats_latest.json`

---

## Configuration

All behavior is controlled via `config.yaml`:

```yaml
runtime_monitoring:
  enabled: true
  poll_interval_seconds: 20
  ai_window_size: 16

vulnerability_monitoring:
  enabled: true
  image_scan_cache_ttl_seconds: 900

cloud:
  enabled: false
  endpoint: ""          # Set your real endpoint here
  api_key_env: "CVE_CLOUD_API_KEY"
```

---

## What the Vulnerable vs Hardened Images Demonstrate

| Issue | Vulnerable | Hardened |
|---|---|---|
| Base image | `python:latest` (unpinned) | `python:3.11-slim` (pinned) |
| User | root (UID 0) | non-root (UID 1000) |
| Secrets | Hardcoded in ENV | Excluded via `.dockerignore` |
| Packages | curl, wget, vim installed | Minimal only |
| Ports | Multiple exposed | Port 5000 only |
| Image size | ~1.2 GB | ~144 MB |

---

## Typical Scan Results

- **88% image size reduction**
- **53% fewer CVEs** after hardening
- **Zero hardcoded secrets**
- **Non-root execution**

---

## Running Tests

```bash
pip install pytest
pytest tests/
```

---

## CI/CD

**GitHub Actions** — runs on every push and pull request:
.github/workflows/security-audit.yml

**GitLab CI** — multi-stage pipeline:
.gitlab-ci.yml

Both enforce vulnerability thresholds and fail the build if critical CVEs exceed the configured limit.

---

## Security

The dashboard now mandates authentication by default to prevent unauthorized access.
- You must set the `DASHBOARD_AUTH_USER` and `DASHBOARD_AUTH_PASSWORD` environment variables before starting the dashboard.
- For local development only, you can bypass authentication by setting `DASHBOARD_ALLOW_INSECURE=true`.
- The dashboard control endpoints are protected against brute-force attacks with rate limiting (10 requests per minute) and overall application limits (200 per day, 50 per hour) via Flask-Limiter.

## Security Checklist

**Container level:**
- [ ] Pinned minimal base image
- [ ] Non-root user
- [ ] No hardcoded secrets
- [ ] `.dockerignore` in place
- [ ] Health checks configured
- [ ] Resource limits set

**Kubernetes level:**
- [ ] Pod Security Standards enforced
- [ ] Network Policies applied
- [ ] RBAC configured
- [ ] ResourceQuota set
- [ ] Secrets used (not ConfigMaps) for sensitive data

**CI/CD level:**
- [ ] Automated scanning on every push
- [ ] Threshold-based build gates
- [ ] SARIF export for GitHub Security tab

---

## Tech Stack

| Component | Technology |
|---|---|
| Vulnerability scanning | Trivy, Grype |
| Config linting | Dockle |
| SBOM generation | Syft |
| Runtime monitoring | Docker SDK for Python |
| Dashboard | Flask + Chart.js |
| Reports | Python + Jinja2 |
| CI/CD | GitHub Actions, GitLab CI |
| Orchestration | Docker Compose, Kubernetes |

---

## Roadmap

- [ ] Real ML anomaly model (IsolationForest trained on labeled container telemetry)
- [ ] Slack / webhook alerting integration
- [ ] SARIF export for GitHub Security tab
- [ ] OpenTelemetry metrics export
- [ ] Grype + Trivy CVE diff view in dashboard

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code style, and PR guidelines.

---

## Packaging for Distribution

You can package the dashboard into a single executable using PyInstaller. This makes it easy to distribute to users who do not have Python or pip installed.

**Build Command:**
```bash
./build.sh
```

**Usage:**
After building, the executable will be located at `dist/cybersec-dashboard`. You can run it directly:
```bash
./dist/cybersec-dashboard
```

**Limitations/Workarounds:**
- PyInstaller can sometimes struggle to correctly bundle dynamic native dependencies from libraries like `scikit-learn` or `numpy` depending on the host OS and libc versions.
- The `build.sh` script explicitly adds several known hidden imports, but if you see `ImportError: ... sklearn ...` when running the binary, you may need to explicitly specify additional hidden imports in the build script.
- The Docker SDK relies on the `docker` binary being present on the host system to function. The packaged executable does not bundle Docker itself.
- Ensure that `config.yaml` is kept in the same directory as the executable, or edit the spec file to bundle it properly.

---

## References

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [NSA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Copyright (c) 2025 noble6 (DeAd_SeC)

---

> 📸 Demo GIF coming soon

<!-- Suggested GitHub Topics: docker security devsecops trivy container-security vulnerability-scanning cybersecurity python -->
