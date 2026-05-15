> 📸 Demo GIF coming soon

# docker-monitor

[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Audit-red?style=for-the-badge)](https://github.com/noble6/docker-monitor)
[![Trivy](https://img.shields.io/badge/Trivy-Scanner-blue?style=for-the-badge)](https://github.com/aquasecurity/trivy)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

An enterprise-grade DevSecOps platform for container security assessment, automated vulnerability scanning, and real-time runtime monitoring.

## 🎯 Project Overview

This production-ready platform provides:
- Automated multi-engine security scanning (Trivy, Dockle, Syft, Grype)
- Real-time Docker runtime threat monitoring
- AI-assisted anomaly detection for runtime metrics
- Interactive web dashboard for visualizing metrics
- CI/CD pipeline integration (GitHub Actions, GitLab CI)
- Kubernetes security configurations
- Multi-format reporting (JSON, HTML, Text)
- Historical trend tracking
- Real-time CVE detection with suggested package fixes
- Cloud check-in API for CVE/runtime telemetry

## 🚀 Quick Start

### 1. Run Basic Audit
```bash
python audit.py
```

### 2. Launch Web Dashboard
```bash
cd dashboard
python app.py
# Open: http://localhost:8080
```

### 3. Run Everything with Docker Compose
```bash
# Configure dashboard auth
export DASHBOARD_AUTH_USER=admin
export DASHBOARD_AUTH_PASSWORD='change-this-password'

docker-compose up -d

# Access:
# - Vulnerable app: http://localhost:5001
# - Hardened app: http://localhost:5002
# - Dashboard: http://localhost:8080

docker-compose down
```

### 4. Deploy to Kubernetes
```bash
# Hardened deployment (production-ready)
kubectl apply -f k8s/deployment-hardened.yaml

# View resources
kubectl get all -n flask-hardened
kubectl get netpol -n flask-hardened
```

### 5. Run Real-Time Threat Engine
```bash
python realtime_threat_engine.py
```
Single snapshot mode:
```bash
RUNTIME_MONITOR_MODE=once python realtime_threat_engine.py
```

## Configuration & Environment Variables

Key configuration is managed via `config.yaml` and environment variables.

| Variable | Description |
|---|---|
| `DASHBOARD_AUTH_USER` | Dashboard admin username |
| `DASHBOARD_AUTH_PASSWORD` | Dashboard admin password |
| `CVE_CLOUD_API_KEY` | API key for cloud telemetry check-in |
| `RUNTIME_MONITOR_MODE` | Set to `once` for single execution or `forever` for continuous |

## Roadmap
- Real ML anomaly model (IsolationForest trained on labeled telemetry)
- Slack/webhook alerting integration
- SARIF export for GitHub Security tab
- OpenTelemetry metrics export

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<!-- Suggested GitHub Topics: docker, security, devsecops, trivy, container-security, vulnerability-scanning, cybersecurity, python -->
